%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(rdp_server_fsm).
-behaviour(gen_fsm).

-compile([{parse_transform, lager_transform}]).

-include("rdp_server.hrl").
-include("rdp_server_internal.hrl").

-export([start_link/3]).
-export([accept/2, initiation/2, mcs_connect/2, mcs_attach_user/2, mcs_chans/2, rdp_clientinfo/2, rdp_capex/2, init_finalize/2, running/2, running/3, raw_mode/2, raw_mode/3]).
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-define(start_timeout_ms, 30000).

-spec start_link(Sock :: term(), Mod :: atom() | {atom(), [term()]}, Sup :: pid()) -> {ok, pid()}.
start_link(Sock, Mod, Sup) ->
    gen_fsm:start_link(?MODULE, [Sock, Mod, Sup], []).

init([LSock, {Mod, InitArgs}, Sup]) ->
    process_flag(trap_exit, true),
    {ok, MPPC} = mppc_nif:new_context(compress),
    {ok, accept, #state{mod = Mod, initargs = InitArgs, sup = Sup, lsock = LSock,
        chansavail=lists:seq(1002,1002+35), mppc = MPPC}, 0};

init([LSock, Mod, Sup]) ->
    process_flag(trap_exit, true),
    {ok, MPPC} = mppc_nif:new_context(compress),
    {ok, accept, #state{mod = Mod, initargs = [], sup = Sup, lsock = LSock,
        chansavail=lists:seq(1002,1002+35), mppc = MPPC}, 0}.

accept(timeout, S = #state{mod = Mod, initargs = InitArgs0, sup = Sup, lsock = LSock}) ->
    % accept a new connection
    {ok, Sock} = gen_tcp:accept(LSock),

    % start our replacement in the pool
    rdp_server_sup:start_frontend(Sup),

    {ok, TRef} = timer:send_after(?start_timeout_ms, startup_timeout),

    % accept sock is in passive mode
    inet:setopts(Sock, [{packet, raw}, {active, once}, {nodelay, true}]),

    Peer = case inet:peername(Sock) of
        {ok, P} -> P;
        _ -> undefined
    end,
    InitArgs1 = [Peer | InitArgs0],
    case erlang:apply(Mod, init, InitArgs1) of
        {ok, ModState} ->
            {next_state, initiation, S#state{
                sock = Sock, peer = Peer, modstate = ModState,
                starttimer = TRef}};
        {stop, Reason, ModState} ->
            {stop, Reason, S#state{
                sock = Sock, peer = Peer, modstate = ModState,
                starttimer = TRef}}
    end.

%% STATE: initiation
%%
%% We have accepted a connection as an RDP server, so we wait for
%% the client to send us the x224 CR (connection request).
%%
%% It contains the first stage of protocol negotiation, as well
%% as a redirect cookie (if the user has one).
%%
initiation({x224_pdu, #x224_cr{class = 0, dst = 0} = Pkt},
        S = #state{mod = Mod, modstate = MS, x224 = X224}) ->

    #x224_cr{src = ThemRef, rdp_cookie = Cookie,
        rdp_protocols = Protos} = Pkt,

    NewX224 = X224#x224_state{them = ThemRef, cr = Pkt},
    % record the requested protocol flags in 'askedfor' -- we need
    % to supply these again later in the MCS connect phase
    S2 = S#state{x224 = NewX224, askedfor=Protos},

    % currently we can only accept TLS/SSL connections, so enforce
    % that here before we call the callback module
    case lists:member(ssl, Protos) of
        true ->
            case Mod:handle_connect(Cookie, Protos, {self(), S2}, MS) of
                {accept, MS2} ->
                    accept_cr([], S2#state{modstate = MS2});
                {accept, SslOpts, MS2} ->
                    accept_cr(SslOpts, S2#state{modstate = MS2});
                {accept_raw, MS2} ->
                    #state{starttimer = ST} = S,
                    timer:cancel(ST),
                    {next_state, raw_mode, S2#state{modstate = MS2}};

                {reject, Reason, MS2} ->
                    reject_cr(Reason, S2#state{modstate = MS2});
                {stop, Reason, MS2} ->
                    {stop, Reason, S2#state{modstate = MS2}}
            end;
        false ->
            reject_cr(ssl_required, S2)
    end.

reject_cr(Reason, S = #state{sock = Sock, x224 = X224}) ->
    #x224_state{them = ThemRef} = X224,
    _ = lager:debug("~p rejecting cr, reason = ~p", [S#state.peer, Reason]),
    UsRef = 1000 + rand:uniform(1000),
    Resp = #x224_cc{src = UsRef, dst = ThemRef,
        rdp_status = error, rdp_error = Reason},
    {ok, RespData} = x224:encode(Resp),
    {ok, Packet} = tpkt:encode(RespData),
    gen_tcp:send(Sock, Packet),

    gen_tcp:close(Sock),
    {stop, normal, S}.

accept_cr(SslOpts, S = #state{x224 = X224}) ->
    #x224_state{them = ThemRef} = X224,

    UsRef = 1000 + rand:uniform(1000),
    Resp = #x224_cc{src = UsRef, dst = ThemRef,
        rdp_selected = [ssl],
        rdp_flags = [extdata, restricted_admin]},
    {ok, RespData} = x224:encode(Resp),
    {ok, Packet} = tpkt:encode(RespData),

    S2 = S#state{x224 = X224#x224_state{us = UsRef}},

    start_tls(mcs_connect, Packet, SslOpts, S2).

start_tls(NextState, Packet, SslOpts,
        S = #state{sock = Sock, sslsock = none}) ->
    ok = inet:setopts(Sock, [{packet, raw}, {active, false}]),
    ok = gen_tcp:send(Sock, Packet),

    Ciphers = [{A,B,C} || {A,B,C} <- ssl:cipher_suites(all, 'tlsv1.2'),
        not (B =:= des_cbc), not (C =:= md5)],

    Ret = ssl:handshake(Sock, [binary, {active, true}, {nodelay, true},
        {ciphers, Ciphers}, {honor_cipher_order, true} | SslOpts], 10000),

    case Ret of
        {ok, SslSock} ->
            {ok, Info} = ssl:connection_information(SslSock),
            Proto = proplists:get_value(protocol, Info),
            Cipher = proplists:get_value(selected_cipher_suite, Info),
            SNIHost = proplists:get_value(sni_hostname, Info, none),
            _ = lager:info("~p: accepted tls ~p (cipher = ~p, sni = ~p)",
                [S#state.peer, Proto, Cipher, SNIHost]),
            ok = ssl:setopts(SslSock, [binary,
                {active, true}, {nodelay, true}]),
            {next_state, NextState,
                S#state{sslsock = SslSock}};

        {error, closed} ->
            {stop, normal, S};

        {error, Err} ->
            _ = lager:debug("~p: tls error: ~p, dropping connection", [S#state.peer, Err]),
            {stop, normal, S}
    end.

%% STATE: raw_mode
%%
%% In this mode we just pass through all the protocol data straight
%% to our callback module. This is to enable proxying from an early
%% stage in the process.
%%
raw_mode({send, Packet}, _From,
        S = #state{sslsock = none, sock = Sock}) ->
    Ret = gen_tcp:send(Sock, Packet),
    {reply, Ret, raw_mode, S}.

raw_mode({start_tls, SslOpts, LastPacket},
        S = #state{sslsock = none}) ->
    start_tls(raw_mode, LastPacket, SslOpts, S);

raw_mode({send_redirect, _, _, _},
        S = #state{}) ->
    {reply, {error, raw_mode}, raw_mode, S};

raw_mode(close, S = #state{sslsock = none, sock = Sock}) ->
    gen_tcp:close(Sock),
    {stop, normal, S};

raw_mode(close, S = #state{sslsock = SslSock}) ->
    _ = rdp_server:send({self(), S}, #mcs_dpu{}),
    timer:sleep(500),
    ssl:close(SslSock),
    {stop, normal, S};

raw_mode({data, Data}, S = #state{mod = Mod, modstate = MS}) ->
    case Mod:handle_raw_data(Data, {self(), S}, MS) of
        {ok, MS2} ->
            {next_state, raw_mode, S#state{modstate = MS2}};
        {stop, Reason, MS2} ->
            {stop, Reason, S#state{modstate = MS2}}
    end;

raw_mode(Event, S = #state{mod = Mod, modstate = MS}) ->
    case Mod:handle_event(Event, {self(), S}, MS) of
        {ok, MS2} ->
            {next_state, raw_mode, S#state{modstate = MS2}};
        {stop, Reason, MS2} ->
            {stop, Reason, S#state{modstate = MS2}}
    end.

%% STATE: mcs_connect
%%
%% We have sent the x224 CC (connection confirm), now we wait for the
%% MCS CI (connect-initial) PDU, to set up the MCS/GCC layers.
%%
%% The MCS CI also contains TSUDs, which are another step in the
%% capability negotiation process. In particular the netchannel TSUD
%% exchange establishes the MCS channel IDs for further exchanges.
%%
%% As we process the client's TSUDs we will build our own (which
%% look a bit different), to send with the MCS CR.
%%
%% All the channels allocated IDs here are added to the waitlist
%% on exit from this state. In the mcs_chans state later we wait
%% for the client to join all of these channels.
%%
mcs_connect({x224_pdu, Pdu}, Data) ->
    % ignore any misc x224 pdus we get at this point (some buggy clients
    % will still send a few more)
    lager:debug("got x224 pdu in mcs_connect: ~s", [x224:pretty_print(Pdu)]),
    {next_state, mcs_connect, Data};

mcs_connect({mcs_pdu, #mcs_ci{} = McsCi},
        S0 = #state{sslsock = SslSock}) ->
    maybe([
        fun(S) ->
            {ok, Tsuds} = tsud:decode(McsCi#mcs_ci.data),
            {continue, [S#state{tsuds = Tsuds}, Tsuds, <<>>]}
        end,
        fun(S = #state{mcs = Mcs}, Tsuds, SoFar) ->
            % allocate our MCS user
            {MyUser, S2} = next_channel(S, 1002),
            {ThemUser, S3} = next_channel(S2, 1007),
            S4 = S3#state{mcs = Mcs#mcs_state{us = MyUser, them = ThemUser}},
            {continue, [S4, Tsuds, SoFar]}
        end,
        fun(S, Tsuds, SoFar) ->
            {ok, Core} = tsud:encode(#tsud_svr_core{
                version=[8,5], requested = S#state.askedfor,
                capabilities = [dynamic_dst]}),
            {continue, [S, Tsuds, <<SoFar/binary, Core/binary>>]}
        end,
        fun(S = #state{mcs = Mcs}, Tsuds, SoFar) ->
            % allocate the I/O channel
            {IoChan, S2} = next_channel(S, 1003),
            {MsgChan, S3} = case lists:keyfind(tsud_msgchannel, 1, Tsuds) of
                false -> {none, S2};
                _ -> next_channel(S2, 1004)
            end,
            S4 = S3#state{mcs = Mcs#mcs_state{iochan = IoChan,
                msgchan = MsgChan}},
            % generate the NET TSUD, allocating any other requested
            % MCS channels
            case lists:keyfind(tsud_net, 1, Tsuds) of
                false ->
                    {ok, Net} = tsud:encode(#tsud_svr_net{
                        iochannel = IoChan, channels = []}),
                    S5 = case MsgChan of
                        none -> S4#state{waitchans = []};
                        _ -> S4#state{waitchans = [MsgChan]}
                    end,
                    {continue, [S5, Tsuds, <<SoFar/binary, Net/binary>>]};

                #tsud_net{channels = ReqChans} ->
                    {S5, ChansRev} = lists:foldl(fun(Chan, {SS, Cs}) ->
                        % by spec we should check for the 'init' flag in
                        % the tsud_net_channel here and only allocate
                        % those that have it set, but some buggy
                        % clients will break if we don't allocate all
                        % of the channels.
                        {C, SS2} = next_channel(SS),
                        Mcs0 = SS2#state.mcs,
                        Chans0 = Mcs0#mcs_state.chans,
                        Mcs1 = Mcs0#mcs_state{
                            chans = Chans0#{C => Chan}},
                        SS3 = SS2#state{mcs = Mcs1},
                        {SS3, [C | Cs]}
                    end, {S4, []}, ReqChans),
                    Chans0 = lists:reverse(ChansRev),
                    Chans1 = case MsgChan of
                        none -> Chans0;
                        _ -> Chans0 ++ [MsgChan]
                    end,
                    % add all the additional channels to the wait list
                    S6 = S5#state{waitchans = Chans1},
                    {ok, Net} = tsud:encode(#tsud_svr_net{
                        iochannel = IoChan, channels = Chans0}),
                    {continue, [S6, Tsuds, <<SoFar/binary, Net/binary>>]}
            end
        end,
        fun(S, Tsuds, SoFar) ->
            % currently we only support TLS/SSL security, so we have no
            % inner-layer RDP security features
            {ok, Sec} = tsud:encode(#tsud_svr_security{
                method = none, level = none}),
            {continue, [S, Tsuds, <<SoFar/binary, Sec/binary>>]}
        end,
        fun(S, Tsuds, SoFar) ->
            #state{mcs = #mcs_state{msgchan = MsgChan}} = S,
            case lists:keyfind(tsud_msgchannel, 1, Tsuds) of
                false ->
                    {continue, [S, Tsuds, SoFar]};
                _ ->
                    % the msgchan is supposed to get an ID, but everyone
                    % seems to ignore this and some things break if it's
                    % not just 0
                    {ok, Bin} = tsud:encode(#tsud_svr_msgchannel{
                        channel = MsgChan}),
                    {continue, [S, Tsuds, <<SoFar/binary, Bin/binary>>]}
            end
        end,
        % if we one day get multitransport support...
        %fun(D, Tsuds, SoFar) ->
        %   case lists:keyfind(tsud_multitransport, 1, Tsuds) of
        %       false ->
        %           {continue, [D, Tsuds, SoFar]};
        %       _ ->
        %           {ok, Bin} = tsud:encode(#tsud_svr_multitransport{}),
        %           {continue, [D, Tsuds, <<SoFar/binary, Bin/binary>>]}
        %   end
        %end,
        fun(S = #state{mcs = Mcs}, _Tsuds, SvrTsuds) ->
            {ok, Cr} = mcsgcc:encode_cr(#mcs_cr{
                data = SvrTsuds, node = Mcs#mcs_state.us}),

            {ok, DtData} = x224:encode(#x224_dt{data = Cr}),
            {ok, Packet} = tpkt:encode(DtData),
            ok = ssl:send(SslSock, Packet),

            {return, {next_state, mcs_attach_user, S}}
        end
    ], [S0]);

% nothing should really do this, but...
mcs_connect({mcs_pdu, Pdu}, Data) ->
    _ = lager:warning("mcs_connect got: ~s", [mcsgcc:pretty_print(Pdu)]),
    {next_state, mcs_connect, Data}.

next_channel(S = #state{chansavail = [Next | Rest]}) ->
    {Next, S#state{chansavail = Rest}}.
next_channel(S = #state{chansavail = Cs}, Pref) ->
    case take_el(Pref, Cs) of
        {true, Without} -> {Pref, S#state{chansavail = Without}};
        {false, [First | Rest]} -> {First, S#state{chansavail = Rest}}
    end.

take_el(_El, []) -> {false, []};
take_el(El, [El | Rest]) -> {true, Rest};
take_el(El, [Next | Rest]) ->
    {State, Rem} = take_el(El, Rest),
    {State, [Next | Rem]}.

%% STATE: mcs_attach_user
%%
%% Wait until we get an mcs_aur (attach user request) and send an mcs_auc
%% back. If we get an mcs_edr at any point here, just ignore it.
%%
mcs_attach_user({x224_pdu, _}, Data) ->
    % ignore any misc x224 pdus too
    {next_state, mcs_attach_user, Data};

mcs_attach_user({mcs_pdu, #mcs_edr{}}, Data) ->
    % ignore it
    {next_state, mcs_attach_user, Data};

mcs_attach_user({mcs_pdu, #mcs_aur{}},
        S = #state{mcs = #mcs_state{them = Them}}) ->
    ok = rdp_server:send({self(), S},
        #mcs_auc{user = Them, status = 'rt-successful'}),
    {next_state, mcs_chans, S};

mcs_attach_user({mcs_pdu, Pdu}, Data) ->
    % this is pretty weird and shouldn't happen
    _ = lager:warning("mcs_attach_user got: ~s", [mcsgcc:pretty_print(Pdu)]),
    {next_state, mcs_attach_user, Data}.

%% STATE: mcs_chans
%%
%% The client will now proceed to join all of the MCS channels we allocated
%% back in the TSUD processing step. Wait until either all channels are
%% joined, or we get sent a ts_info early (some buggy clients, mostly
%% rdesktop and its derivatives, don't join all channels).
%%
mcs_chans({mcs_pdu, #mcs_cjr{user = Them, channel = Chan}},
        S = #state{waitchans = Chans,
            mcs = #mcs_state{them = Them, us = Us}}) ->
    Remaining = Chans -- [Chan],
    S2 = S#state{waitchans = Remaining},

    ok = rdp_server:send({self(), S},
        #mcs_cjc{user = Them, channel = Chan,
            status = 'rt-successful'}),

    if
        (length(Remaining) == 0) ->
            _ = lager:debug("~p mcs_chans all ok (chans = ~p)", [
                S#state.peer, S2#state.mcs#mcs_state.chans]),
            {next_state, rdp_clientinfo, S2};
        true ->
            {next_state, mcs_chans, S2}
    end;

mcs_chans({mcs_pdu, Pdu = #mcs_data{user = Them, channel = IoChan}},
        S = #state{waitchans = Chans,
            mcs = #mcs_state{them = Them, iochan = IoChan}}) ->
    % if an RDP BASIC packet (should only be a ts_info if any) arrives
    % on the io channel early (before all channels are joined), we are
    % probably talking to buggy rdesktop. go straight to the
    % rdp_clientinfo state.
    #mcs_data{data = RdpData} = Pdu,
    case rdpp:decode_basic(RdpData) of
        {ok, #ts_info{}} ->
            _ = lager:debug("got ts_info while still waiting for chans (missing = ~p)", [Chans]),
            rdp_clientinfo({mcs_pdu, Pdu}, S);
        {ok, RdpPkt} ->
            _ = lager:warning("mcs_chans got: ~s", [rdpp:pretty_print(RdpPkt)]),
            {next_state, mcs_chans, S};
        _ ->
            _ = lager:warning("mcs_chans got: ~s", [mcsgcc:pretty_print(Pdu)]),
            {next_state, mcs_chans, S}
    end;

mcs_chans({mcs_pdu, Pdu = #mcs_data{user = Them, channel = Them}},
        S = #state{mcs = #mcs_state{them = Them}}) ->
    % this seems to happen sometimes and doesn't seem to be anything
    % interesting, so let's just ignore it (are you getting the impression
    % that this protocol is a mess yet?)
    #mcs_data{data = RdpData} = Pdu,
    case rdpp:decode_basic(RdpData) of
        {ok, RdpPkt} ->
            _ = lager:debug("mcs_chans got on user chan: ~s", [rdpp:pretty_print(RdpPkt)]);
        _ ->
            _ = lager:debug("mcs_chans got on user chan: ~s", [mcsgcc:pretty_print(Pdu)])
    end,
    {next_state, mcs_chans, S}.

%% STATE: rdp_clientinfo
%%
%% Once all MCS channels have been joined, we proceed to wait for and
%% process the client's TS_INFO packet. This contains RDP capability
%% structs, as well as tonnes of other stuff.
%%
%% It's also where we negotiate details like resolution and colour depth
%% for the session.
%%
rdp_clientinfo({mcs_pdu, Pdu = #mcs_data{user = Them, channel = IoChan}},
        S = #state{mcs = #mcs_state{them = Them, us = Us, iochan = IoChan}}) ->
    #mcs_data{data = RdpData} = Pdu,
    case rdpp:decode_basic(RdpData) of
        {ok, #ts_info{} = InfoPkt} ->
            % get the maximum supported MPPC compression level from the client
            % and stash it in our mppc context. we'll use it for fastpath
            % updates later.
            #ts_info{compression = ComprLevel} = InfoPkt,
            RealComprLevel = case ComprLevel of
                '8k' -> '8k';
                _ -> '64k'
            end,
            #state{mppc = MPPC} = S,
            ok = mppc_nif:set_level(MPPC, RealComprLevel),

            % first up, send them the license confirmation packet
            {ok, LicData} = rdpp:encode_basic(
                #ts_license_vc{secflags=[encrypt_license]}),
            ok = rdp_server:send({self(), S}, #mcs_srv_data{
                user = Us, channel = IoChan, data = LicData}),

            % now, work out the colour depth we're going to use
            Core = #tsud_core{} = lists:keyfind(tsud_core, 1, S#state.tsuds),
            #state{mod = Mod, modstate = MS0} = S,
            % if the callback module wants to choose, use that
            Format = case erlang:function_exported(Mod, choose_format, 3) of
                true ->
                    {F, MS1} = Mod:choose_format(Core#tsud_core.color,
                        Core#tsud_core.colors, MS0),
                    F;
                false ->
                    MS1 = MS0,
                    % if they requested 16bpp explicitly, use it
                    case Core#tsud_core.color of
                        '16bpp' -> '16bpp';
                        _ ->
                            % otherwise try either 24bpp or 16bpp
                            case lists:member('24bpp', Core#tsud_core.colors) of
                                true -> '24bpp';
                                false -> '16bpp'
                            end
                    end
            end,
            Bpp = case Format of
                '4bpp' -> 4;
                '8bpp' -> 8;
                '15bpp' -> 15;
                '16bpp' -> 16;
                '24bpp' -> 24;
                '32bpp' -> 32
            end,
            % crash if the format we're trying to choose isn't on
            % the client's supported list
            true = lists:member(Format, Core#tsud_core.colors),

            % if they sent us multi-monitor, we have to send a canvas size
            % of the union of all the monitors in the bitmap caps (otherwise
            % mstsc will try to scale the size we send to the total monitor
            % footprint, which will go pretty weird)
            %
            % note this works in concert with us sending the monitor layout
            % pdu later (in init_finalize)
            {W, H} = case lists:keyfind(tsud_monitor, 1, S#state.tsuds) of
                #tsud_monitor{monitors = Ms} ->
                    MaxRight = lists:max([R ||
                        #tsud_monitor_def{right = R} <- Ms]),
                    MaxBottom = lists:max([B ||
                        #tsud_monitor_def{bottom = B} <- Ms]),
                    {MaxRight + 1, MaxBottom + 1};
                _ ->
                    {Core#tsud_core.width, Core#tsud_core.height}
            end,

            % this is meant to be "random" by the GCC spec, but
            % some clients seem to break if it's not set to 1
            Rand = 1,
            <<ShareId:32/big>> = <<Rand:16/big, Us:16/big>>,

            % now we build our TS_DEMAND packet
            {ok, DaPkt} = rdpp:encode_sharecontrol(#ts_demand{
                shareid = ShareId,
                channel = Us,

                % supposedly you can change this, but it's hard-coded
                % into everything else...
                sourcedesc = <<"RDP", 0>>,

                capabilities = [
                    % seems like this needs to always come first
                    #ts_cap_share{channel = Us},
                    % yeah we are totally Windows NT
                    #ts_cap_general{
                        os = [windows, winnt],
                        flags = [suppress_output, refresh_rect,
                            short_bitmap_hdr, autoreconnect,
                            long_creds, salted_mac, fastpath]},
                    % we support dynamic virtual channels
                    % (actually we don't, but we have to lie here)
                    #ts_cap_vchannel{},
                    % yeah fonts too, totally
                    #ts_cap_font{},
                    % some versions of MS RDP refuse to believe we're
                    % using a modern RDP protocol version unless we
                    % say we support NSCODEC, so do that
                    #ts_cap_bitmap_codecs{codecs = [
                        #ts_cap_bitmap_codec{
                            codec = nscodec,
                            id = 1,
                            properties = [
                                {dynamic_fidelity, true},
                                {subsampling, true},
                                {color_loss_level, 3}]}
                    ]},
                    #ts_cap_bitmap{
                        % give the client whatever size session they
                        % asked for
                        width = W,
                        height = H,
                        % but use the colour depth we worked out above
                        bpp = Bpp,
                        flags = [resize, compression, dynamic_bpp,
                            skip_alpha, multirect]},
                    % we want EGDI support
                    #ts_cap_order{},
                    #ts_cap_pointer{},
                    #ts_cap_input{
                        flags = [mousex, scancodes, unicode, fastpath,
                            fastpath2],
                        kbd_layout = 0,
                        kbd_type = 0,
                        kbd_fun_keys = 0},
                    #ts_cap_multifrag{maxsize = 4*1024*1024},
                    #ts_cap_large_pointer{},
                    #ts_cap_colortable{},
                    #ts_cap_surface{}
                ]
            }),

            ok = rdp_server:send({self(), S}, #mcs_srv_data{
                user = Us, channel = IoChan, data = DaPkt}),

            % if they indicated multi-monitor support, send them the monitor
            % layout pdu now so their client knows we accepted it
            Mons = case lists:keyfind(tsud_monitor, 1, S#state.tsuds) of
                #tsud_monitor{monitors = M} ->
                    M;
                _ ->
                    [#tsud_monitor_def{left = 0, top = 0,
                                       right = W, bottom = H,
                                       flags = [primary]}]
            end,
            #tsud_core{capabilities = Caps} = Core,
            case lists:member(monitor_layout, Caps) of
                true ->
                    {ok, MonitorMap} = rdpp:encode_sharecontrol(
                        #ts_sharedata{
                            channel = Us, shareid = ShareId,
                            data = #ts_monitor_layout{monitors = Mons}}),
                    ok = rdp_server:send({self(), S}, #mcs_srv_data{
                        user = Us, channel = IoChan, data = MonitorMap});
                _ ->
                    ok
            end,

            % now we proceed to the final capabilities exchange
            {next_state, rdp_capex, S#state{
                shareid = ShareId, client_info = InfoPkt, bpp = Bpp,
                modstate = MS1}};

        {ok, RdpPkt} ->
            % what?
            _ = lager:warning("rdp packet: ~s", [rdpp:pretty_print(RdpPkt)]),
            {next_state, rdp_clientinfo, S};

        Other ->
            % if this happens things have gone bad
            {stop, {bad_protocol, Other}, S}
    end;

rdp_clientinfo({mcs_pdu, #mcs_cjr{user = Them, channel = Chan}},
        S = #state{mcs = #mcs_state{them = Them, us = Us, iochan = IoChan}}) ->
    % Some buggy clients seem to send a CJR for the iochan?
    case Chan of
        IoChan ->
            lager:debug("~p sent CJR for io channel, responding ok (but this "
                "is a spec violation)", [S#state.peer]),
            ok = rdp_server:send({self(), S},
                #mcs_cjc{user = Them, channel = Chan,
                    status = 'rt-successful'}),
            {next_state, rdp_clientinfo, S};
        OtherChan ->
            lager:debug("~p sent CJR for unknown channel ~B?? ignoring it",
                [S#state.peer, Chan]),
            {next_state, rdp_clientinfo, S}
    end;

rdp_clientinfo({mcs_pdu, Pdu = #mcs_data{user = Them, channel = Them}},
        S = #state{mcs = #mcs_state{them = Them}}) ->
    % just ignore any other RDP BASIC packets we get on the user channel
    #mcs_data{data = RdpData} = Pdu,
    case rdpp:decode_basic(RdpData) of
        {ok, RdpPkt} ->
            _ = lager:debug("rdp_clientinfo got on user chan: ~s", [rdpp:pretty_print(RdpPkt)]);
        _ ->
            _ = lager:debug("rdp_clientinfo got on user chan: ~s", [mcsgcc:pretty_print(Pdu)])
    end,
    {next_state, rdp_clientinfo, S}.

%% STATE: rdp_capex
%%
%% After we send the TS_DEMAND, we will receive a matching TS_CONFIRM
%% back from the client.
%%
rdp_capex({mcs_pdu, Pdu = #mcs_data{user = Them, channel = IoChan}},
        S = #state{shareid = ShareId,
            mcs = #mcs_state{them = Them, iochan = IoChan}}) ->

    case rdpp:decode_sharecontrol(Pdu#mcs_data.data) of
        {ok, #ts_confirm{shareid = ShareId, capabilities = Caps}} ->
            % grab the client OS details out and print them, this is
            % useful for accounting and debugging
            #ts_cap_general{os = OS, flags = Fl} = lists:keyfind(
                ts_cap_general, 1, Caps),
            _ = lager:debug("client OS = ~p, flags = ~p", [OS, Fl]),
            {next_state, init_finalize, S#state{caps = Caps}};

        {ok, _RdpPkt} ->
            % just drop it for now
            {next_state, rdp_capex, S};

        Wat ->
            % uhhh
            case rdpp:decode_ts_confirm(1, Pdu#mcs_data.data) of
                {ok, #ts_confirm{shareid = ShareId, capabilities = Caps}} ->
                    {next_state, init_finalize, S#state{caps = Caps}};
                Wat2 ->
                    _ = lager:error("~p WAT: ~p => ~p then ~p", [S#state.peer, Pdu#mcs_data.data, Wat, Wat2]),
                    % lolwut bro
                    {next_state, rdp_capex, S}
            end
    end.

%% STATE: init_finalize
%%
%% Capabilities exchange finished, we now wait for the sync and control
%% packets. Rather than expand these out into individual states, we just
%% handle replying to all of them here one by one, and on the last
%% of the exchange (the font list PDU), we proceed on to full
%% normal operation.
%%
init_finalize({fp_pdu, #fp_pdu{}}, S = #state{}) ->
    % if we get fastpath info here, just ignore it (some clients send
    % the initial ts_sync through fastpath, but don't expect a reply)
    {next_state, init_finalize, S};

init_finalize({mcs_pdu, Pdu = #mcs_data{user = Them, channel = IoChan}},
        S = #state{shareid = ShareId, mod = Mod, modstate = MS, starttimer = ST,
            mcs = #mcs_state{them = Them, us = Us, iochan = IoChan}}) ->
    case rdpp:decode_sharecontrol(Pdu#mcs_data.data) of
        {ok, #ts_sharedata{shareid = ShareId, data = #ts_sync{}}} ->
            {ok, SyncData} = rdpp:encode_sharecontrol(
                #ts_sharedata{
                    channel = Us, shareid = ShareId,
                    data = #ts_sync{user = Us}}),
            ok = rdp_server:send({self(), S}, #mcs_srv_data{
                user = Us, channel = IoChan, data = SyncData}),
            {next_state, init_finalize, S};

        {ok, #ts_sharedata{shareid = ShareId, data =
                #ts_control{action = cooperate}}} ->
            {ok, CoopData} = rdpp:encode_sharecontrol(
                #ts_sharedata{
                    channel = Us, shareid = ShareId,
                    data = #ts_control{
                        action = cooperate, controlid = Us,
                        grantid = Them}}),
            ok = rdp_server:send({self(), S}, #mcs_srv_data{
                user = Us, channel = IoChan, data = CoopData}),
            {next_state, init_finalize, S};

        {ok, #ts_sharedata{shareid = ShareId, data =
                #ts_control{action = request}}} ->
            {ok, GrantData} = rdpp:encode_sharecontrol(
                #ts_sharedata{
                    channel = Us, shareid = ShareId,
                    data = #ts_control{
                        action = granted, controlid = Us,
                        grantid = Them}}),
            ok = rdp_server:send({self(), S}, #mcs_srv_data{
                user = Us, channel = IoChan, data = GrantData}),
            {next_state, init_finalize, S};

        {ok, #ts_sharedata{shareid = ShareId, data =
            #ts_fontlist{}}} ->
            {ok, FontMap} = rdpp:encode_sharecontrol(
                #ts_sharedata{
                    channel = Us, shareid = ShareId,
                    data = #ts_fontmap{}}),
            ok = rdp_server:send({self(), S}, #mcs_srv_data{
                user = Us, channel = IoChan, data = FontMap}),

            % make sure the mouse pointer is visible
            ok = rdp_server:send_update({self(), S},
                #fp_update_mouse{mode = default}),

            S1 = start_vchan_fsms(S),
            Server = {self(), S1},
            case Mod:init_ui(Server, MS) of
                {ok, MS2} ->
                    S2 = S1#state{modstate = MS2},
                    S3 = case S#state.mcs of
                        #mcs_state{msgchan = none} ->
                            S2;
                        _ ->
                            {ok, T} = timer:send_interval(1000, check_ping),
                            S2#state{pingtimer = T}
                    end,
                    timer:cancel(ST),
                    {next_state, running, S3};
                {stop, Reason, MS2} ->
                    {stop, Reason, S#state{modstate = MS2}}
            end;

        {ok, #ts_sharedata{}} ->
            % ignore other sharedata ops, we don't need to reply to them
            {next_state, init_finalize, S};

        {ok, _RdpPkt} ->
            {next_state, rdp_capex, S}

    end.

%% STATE: running
%%
%% Regular operation, receiving input events from the user's client and
%% writing back display updates etc.
%%
%% The only transitions out of here are:
%%  - back to rdp_capex, if we see something that isn't a sharedata
%%  - termination of the session
%%
running({send, Packet}, _From, S = #state{sslsock = SslSock}) ->
    Ret = ssl:send(SslSock, Packet),
    {reply, Ret, running, S};
running({send_mcs, McsPkt}, _From, S = #state{}) ->
    rdp_server:send({self(), S}, McsPkt),
    {reply, ok, running, S};
running({send_update, TsUpdate}, _From, S = #state{}) ->
    rdp_server:send_update({self(), S}, TsUpdate),
    {reply, ok, running, S};

running(get_pings, _From, S = #state{lastpings = Q}) ->
    {reply, {ok, queue:to_list(Q)}, running, S}.

running(close,
        S = #state{shareid = ShareId, sslsock = SslSock,
            mcs = #mcs_state{us = Us, iochan = IoChan}}) ->
    _ = lager:debug("sending deactivate and close"),
    {ok, Deact} = rdpp:encode_sharecontrol(
        #ts_deactivate{channel = Us, shareid = ShareId}),

    Ret = rdp_server:send({self(), S}, #mcs_srv_data{
        user = Us, channel = IoChan, data = Deact}),
    case Ret of
        ok ->
            _ = rdp_server:send({self(), S}, #mcs_dpu{}),
            timer:sleep(500),
            ssl:shutdown(SslSock, write),
            timer:sleep(500),
            ssl:close(SslSock),
            {stop, normal, S};

        {error, closed} ->
            % some clients disconnect right away when they get redir
            ssl:close(SslSock),
            {stop, normal, S}
    end;

running({mcs_pdu, #mcs_data{user = Them, channel = MsgChan, data = D}},
        S = #state{mcs = #mcs_state{them = Them, msgchan = MsgChan}}) ->
    case rdpp:decode_basic(D) of
        {ok, #ts_autodetect_resp{pdu = #rdp_rtt{seq = Seq}}} ->
            InTime = erlang:system_time(microsecond),
            #state{pings = Pings0} = S,
            case Pings0 of
                #{Seq := OutTime} ->
                    Pings1 = maps:remove(Seq, Pings0),
                    DeltaMillis = (InTime - OutTime) / 1000.0,
                    #state{lastpings = Q0} = S,
                    Q1 = queue:in(DeltaMillis, Q0),
                    Q2 = case queue:len(Q1) of
                        N when N > 16 ->
                            {{value, _}, QQ} = queue:out(Q1),
                            QQ;
                        _ ->
                            Q1
                    end,
                    S2 = S#state{lastpings = Q2, pings = Pings1},
                    {next_state, running, S2};
                _ ->
                    _ = lager:warning("got unsolicited ping reply? seq = %p",
                        [Seq]),
                    {next_state, running, S}
            end;
        {ok, TsPdu} ->
            _ = lager:warning("unhandled msgchan pdu: ~p", [rdpp:pretty_print(TsPdu)]),
            {next_state, running, S};
        _ ->
            _ = lager:warning("got invalid data on msgchan: ~p", [D]),
            {next_state, running, S}
    end;

running(check_ping, S = #state{pings = Pings0,
        mcs = #mcs_state{msgchan = MsgChan, us = Us}}) ->
    Seq = rand:uniform((1 bsl 16) - 1),
    {ok, D} = rdpp:encode_basic(
        #ts_autodetect_req{pdu = #rdp_rtt{seq = Seq}}),
    Ret = rdp_server:send({self(), S}, #mcs_srv_data{
        user = Us, channel = MsgChan, data = D}),
    Now = erlang:system_time(microsecond),
    case Ret of
        ok ->
            Pings1 = Pings0#{Seq => Now},
            {next_state, running, S#state{pings = Pings1}};
        {error, closed} ->
            _ = lager:debug("check_ping detected closed socket"),
            running(close, S);
        Err ->
            _ = lager:warning("check_ping error: ~p", [Err]),
            {next_state, running, S}
    end;

running({send_redirect, Opts},
        S = #state{shareid = ShareId,
            mcs = #mcs_state{us = Us, iochan = IoChan}}) ->
    #{session_id := SessId, cookie := Cookie} = Opts,
    Flags = maps:get(flags, Opts, []),
    Fqdn = case maps:get(fqdn, Opts, undefined) of
        undefined -> [];
        FqdnStr -> unicode:characters_to_binary([FqdnStr, 0], unicode, {utf16, little})
    end,
    NetAddress = case maps:get(address, Opts, undefined) of
        undefined -> [];
        NetAddrStr -> unicode:characters_to_binary([NetAddrStr, 0], unicode, {utf16, little})
    end,
    {ok, Redir} = rdpp:encode_sharecontrol(
        #ts_redir{
            channel = Us,
            shareid = ShareId,
            sessionid = SessId,
            flags = Flags,
            fqdn = Fqdn,
            address = NetAddress,
            cookie = <<Cookie/binary, 16#0d, 16#0a>>
        }),
    McsPkt = #mcs_srv_data{user = Us, channel = IoChan, data = Redir},
    resend_redir(McsPkt, 500, S);

running({fp_pdu, #fp_pdu{contents = Evts}}, S = #state{}) ->
    do_events(Evts, S);

running({mcs_pdu, Pdu = #mcs_data{user = Them, channel = IoChan}},
        S = #state{shareid = ShareId,
            mcs = #mcs_state{them = Them, iochan = IoChan}}) ->
    case rdpp:decode_sharecontrol(Pdu#mcs_data.data) of
        {ok, #ts_sharedata{shareid = ShareId, data =
                #ts_input{events = Evts}}} ->
            do_events(Evts, S);

        {ok, #ts_sharedata{shareid = ShareId, data =
                D = #ts_suppress_output{}}} ->
            do_events([D], S);

        {ok, #ts_sharedata{shareid = ShareId, data =
                D = #ts_refresh_rect{}}} ->
            do_events([D], S);

        {ok, #ts_sharedata{shareid = ShareId, data =
                #ts_shutdown{}}} ->
            running(close, S);

        {ok, #ts_sharedata{data = D}} ->
            _ = lager:debug("unhandled sharedata: ~p", [D]),
            {next_state, running, S};

        {ok, _RdpPkt} ->
            {next_state, rdp_capex, S}
    end;

running({mcs_pdu, Pdu = #mcs_data{user = Them, channel = Chan}},
        S = #state{chanfsms = Fsms, vchfrags = ChFrags0,
                   mcs = #mcs_state{them = Them, chans = Chans}}) ->
    % data can come in on other static channels too, not just iochan
    #mcs_data{data = Data} = Pdu,
    case Chans of
        #{Chan := #tsud_net_channel{name = Name}} ->
            Frags0 = maps:get(Chan, ChFrags0, []),
            case rdpp:decode_vchan(Data, Frags0) of
                {ok, VPkt = #ts_vchan{}} ->
                    ChFrags1 = maps:remove(Chan, ChFrags0),
                    S1 = S#state{vchfrags = ChFrags1},
                    case Fsms of
                        #{Chan := {Mod, Pid}} ->
                            ok = Mod:handle_pdu(Pid, VPkt);
                        _ ->
                            _ = lager:warning(
                                "unhandled data on vchannel ~p (~p): ~s",
                                [Name, Chan, rdpp:pretty_print(VPkt)])
                    end,
                    {next_state, running, S1};
                {fragment, Frags1} ->
                    ChFrags1 = ChFrags0#{Chan => Frags1},
                    S1 = S#state{vchfrags = ChFrags1},
                    {next_state, running, S1};
                _ ->
                    _ = lager:warning("got invalid data on vchannel ~p (~p): ~p", [Name, Chan, Data]),
                    {next_state, running, S}
            end;

        _ ->
            _ = lager:warning("got data on unknown vchannel ~p: ~p", [Chan, Data]),
            {next_state, running, S}
    end;

running({x224_pdu, #x224_dr{}}, S = #state{sslsock = SslSock}) ->
    ssl:close(SslSock),
    {stop, normal, S};

running(Event, S = #state{mod = Mod, modstate = MS}) ->
    Server = {self(), S},
    case Mod:handle_event(Event, Server, MS) of
        {ok, MS2} ->
            {next_state, running, S#state{modstate = MS2}};
        {stop, Reason, MS2} ->
            {stop, Reason, S#state{modstate = MS2}}
    end.

resend_redir(_McsPkt, Sleep, S = #state{sock = Sock}) when (Sleep > 5000) ->
    lager:debug("client refusing to close after ts_redir, forcing it"),
    ssl:shutdown(Sock, write),
    timer:sleep(500),
    ssl:close(Sock),
    {stop, normal, S};
resend_redir(McsPkt, Sleep, S = #state{sslsock = Sock}) ->
    {ok, McsData} = mcsgcc:encode_dpdu(McsPkt),
    {ok, DtData} = x224:encode(#x224_dt{data = McsData}),
    {ok, Packet} = tpkt:encode(DtData),
    case ssl:send(Sock, Packet) of
        ok ->
            receive
                {ssl_closed, Sock} ->
                    lager:debug("closed after ts_redir"),
                    ssl:close(Sock),
                    {stop, normal, S}
            after Sleep ->
                resend_redir(McsPkt, Sleep * 2, S)
            end;
        {error, closed} ->
            lager:debug("closed after ts_redir"),
            ssl:close(Sock),
            {stop, normal, S};
        Other ->
            {stop, Other, S}
    end.

do_events([], S) -> {next_state, running, S};
do_events([Event | Rest], S = #state{mod = Mod, modstate = MS}) ->
    Server = {self(), S},
    case Mod:handle_event(Event, Server, MS) of
        {ok, MS2} ->
            do_events(Rest, S#state{modstate = MS2});
        {stop, Reason, MS2} ->
            {stop, Reason, S#state{modstate = MS2}}
    end.

%
% other handlers and utility functions
%

queue_remainder(Sock, Bin) when byte_size(Bin) > 0 ->
    self() ! {tcp, Sock, Bin};
queue_remainder(_, _) -> ok.

-ifdef(DEBUG).
debug_print_data(<<>>) -> ok;
debug_print_data(Bin) ->
    case rdpp:decode_connseq(Bin) of
        {ok, {fp_pdu, _Pdu}, Rem} ->
            %error_logger:info_report(["frontend rx fastpath:\n", fastpath:pretty_print(Pdu)]);
            debug_print_data(Rem);
        {ok, {x224_pdu, Pdu}, Rem} ->
            error_logger:info_report(["frontend rx x224:\n", x224:pretty_print(Pdu)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu = #mcs_data{data = RdpData}}, Rem} ->
            case rdpp:decode_basic(RdpData) of
                {ok, Rec} ->
                    error_logger:info_report(["frontend rx rdp_basic:\n", rdpp:pretty_print(Rec)]);
                _ ->
                    case rdpp:decode_sharecontrol(RdpData) of
                        {ok, Rec} ->
                            error_logger:info_report(["frontend rx rdp_sharecontrol\n", rdpp:pretty_print(Rec)]);
                        _ ->
                            error_logger:info_report(["frontend rx mcs:\n", [mcsgcc:pretty_print(Pdu)]])
                    end
            end,
            debug_print_data(Rem);
        {ok, {mcs_pdu, McsCi = #mcs_ci{}}, Rem} ->
            {ok, Tsuds} = tsud:decode(McsCi#mcs_ci.data),
            error_logger:info_report(["frontend rx ci with tsuds: ", tsud:pretty_print(Tsuds)]),
            debug_print_data(Rem);
        {ok, {mcs_pdu, Pdu}, Rem} ->
            error_logger:info_report(["frontend rx mcs:\n", [mcsgcc:pretty_print(Pdu)]]),
            debug_print_data(Rem);
        _ -> ok
    end.
-endif.

%% @private
handle_info(startup_timeout, State, S = #state{}) ->
    _ = lager:debug("startup timeout (in ~p), closing", [State]),
    {stop, normal, S};

handle_info({tcp, Sock, Bin}, raw_mode, S = #state{sock = Sock}) ->
    raw_mode({data, Bin}, S);
handle_info({tcp, Sock, Bin}, State, #state{sock = Sock} = S)
        when (State =:= initiation) or (State =:= mcs_connect) ->
    % we have to use decode_connseq here to avoid ambiguity in the asn.1 for
    % the mcs_ci
    case rdpp:decode_connseq(Bin) of
        {ok, Evt, Rem} ->
            queue_remainder(Sock, Rem),
            ?MODULE:State(Evt, S);
        {error, Reason} ->
            _ = lager:warning("~p connseq decode fail in ~p: ~p", [S#state.peer, State, Reason]),
            % the pre-TLS TCP socket is in active-once mode, so we need to
            % re-arm it here or we will never get called again
            inet:setopts(Sock, [{active, once}]),
            {next_state, State, S}
    end;
handle_info({tcp, Sock, Bin}, State, #state{sock = Sock} = S) ->
    case rdpp:decode_server(Bin) of
        {ok, Evt, Rem} ->
            queue_remainder(Sock, Rem),
            ?MODULE:State(Evt, S);
        {error, Reason} ->
            _ = lager:warning("~p decode fail in ~p: ~p", [S#state.peer, State, Reason]),
            {next_state, State, S}
    end;

handle_info({ssl, SslSock, Bin}, raw_mode, #state{sslsock = SslSock} = S) ->
    raw_mode({data, Bin}, S);

handle_info({ssl, SslSock, Bin}, State,
        S = #state{sock = Sock, sslsock = SslSock}) ->
    handle_info({tcp, Sock, Bin}, State, S);

handle_info({ssl_closed, Sock}, State, #state{sslsock = Sock} = S) ->
    case State of
        initiation -> ok;
        mcs_connect -> ok;
        _ -> _ = lager:debug("ssl closed by remote side")
    end,
    {stop, normal, S};

handle_info({ssl_error, Sock, Reason}, State, #state{sslsock = Sock} = S) ->
    case State of
        initiation -> ok;
        mcs_connect -> ok;
        _ -> _ = lager:debug("ssl error from remote side: ~p", [Reason])
    end,
    ssl:close(Sock),
    {stop, normal, S};

handle_info({tcp_closed, Sock}, State, #state{sock = Sock} = S) ->
    case State of
        initiation -> ok;
        mcs_connect -> ok;
        _ -> _ = lager:debug("tcp closed by remote side")
    end,
    {stop, normal, S};

handle_info({tcp_error, Sock, Reason}, State, #state{sock = Sock} = S) ->
    case State of
        initiation -> ok;
        mcs_connect -> ok;
        _ -> _ = lager:debug("tcp error from remote side: ~p", [Reason])
    end,
    gen_tcp:close(Sock),
    {stop, normal, S};

handle_info({'EXIT', Pid, Reason}, State,
        S = #state{watchkids = WKs, sslsock = SslSock}) ->
    case lists:member(Pid, WKs) of
        true ->
            _ = lager:debug("going down due to loss of watched child ~p: ~p", [Pid, Reason]),
            _ = lager:debug("sending dpu"),
            _ = rdp_server:send({self(), S}, #mcs_dpu{}),
            ssl:close(SslSock),
            {stop, normal, S};
        false ->
            _ = lager:debug("unwatched child ~p died: ~p", [Pid, Reason]),
            {next_state, State, S}
    end;

handle_info(check_ping, State, S) ->
    ?MODULE:State(check_ping, S);

handle_info(Msg, running, S = #state{mod = Mod, modstate = MS}) ->
    case erlang:function_exported(Mod, handle_info, 3) of
        true ->
            case Mod:handle_info(Msg, {self(), S}, MS) of
                {ok, MS2} ->
                    {next_state, running, S#state{modstate = MS2}};
                {stop, Reason, MS2} ->
                    {stop, Reason, S#state{modstate = MS2}}
            end;
        false ->
            lager:debug("unhandled message (no handle_info): ~p", [Msg]),
            {next_state, running, S}
    end;
handle_info(Msg, State, S) ->
    lager:debug("unhandled message in state ~p: ~p", [State, Msg]),
    {next_state, State, S}.

handle_event({watch_child, Pid}, State,
        S = #state{watchkids = WKs}) ->
    {next_state, State, S#state{watchkids = [Pid | WKs]}};
handle_event(Ev, _State, #state{} = S) ->
    {stop, {bad_event, Ev}, S}.

handle_sync_event(get_state, _From, State, S = #state{}) ->
    {reply, {ok, S}, State, S};
handle_sync_event(Ev, _From, _State, #state{} = S) ->
    {stop, {bad_event, Ev}, S}.

start_vchan_fsms(S0 = #state{mcs = Mcs, chanfsms = Fsms0}) ->
    #mcs_state{chans = Chans} = Mcs,
    Fsms1 = maps:fold(fun (Id, Chan, Acc0) ->
        #tsud_net_channel{name = Name} = Chan,
        case string:to_lower(Name) of
            "cliprdr" ->
                {ok, Pid} = cliprdr_fsm:start_link({self(), S0}, Id),
                Acc0#{Id => {cliprdr_fsm, Pid}};
            "rdpdr" ->
                {ok, Pid} = rdpdr_fsm:start_link({self(), S0}, Id),
                Acc0#{Id => {rdpdr_fsm, Pid}};
            _ -> Acc0
        end
    end, Fsms0, Chans),
    S0#state{chanfsms = Fsms1}.

%% @private
terminate(Reason, State, S = #state{peer = P, mod = Mod, modstate = MS}) ->
    case State of
        initiation -> ok;
        mcs_connect -> ok;
        _ ->
            _ = lager:debug("rdp_server_fsm terminating due to ~p, "
                "was connected to ~p in state ~p", [Reason, P, State])
    end,
    Mod:terminate({self(), S}, MS).

%% @private
% default handler
code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

maybe([], _Args) -> error(no_return);
maybe([Fun | Rest], Args) ->
    case apply(Fun, Args) of
        {continue, NewArgs} ->
            maybe(Rest, NewArgs);
        {return, Value} ->
            Value
    end.
