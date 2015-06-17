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

-module(rdp_server).

-include("rdp_server.hrl").
-include("rdp_server_internal.hrl").

-export([
    send/2, send_raw/2, send_update/2, start_tls/3,
    mcs_state/1, x224_state/1, get_tsuds/1, get_caps/1,
    get_canvas/1, get_redir_support/1, get_autologon/1,
    send_redirect/3, close/1, watch_child/2
    ]).

-opaque server() :: {pid(), #state{}}.
-export_type([server/0]).

-callback init(Peer :: {inet:ip_address(), Port :: integer()}) -> {ok, State :: term()} | {stop, Reason :: term(), State :: term()}.

-callback handle_connect(Cookie :: binary(), Protocols :: [atom()], Server :: server(), State :: term()) -> {accept, NewState :: term()} | {accept, SslOptions :: [term()], NewState :: term()} | {accept_raw, NewState :: term()} | {reject, Reason :: atom(), NewState :: term()} | {stop, Reason :: term(), NewState :: term()}.

-callback init_ui(Server :: server(), State :: term()) -> {ok, NewState :: term()} | {stop, Reason :: term(), NewState :: term()}.

-callback handle_event(Event :: term(), Server :: server(), State :: term()) -> {ok, NewState :: term()} | {stop, Reason :: term(), NewState :: term()}.

-callback handle_raw_data(Data :: binary(), Server :: server(), State :: term()) -> {ok, NewState :: term()} | {stop, Reason :: term(), NewState :: term()}.

-callback terminate(Server :: server(), State :: term()) -> ok.

-spec x224_state(server()) -> #x224_state{}.
x224_state({_, #state{x224 = S}}) -> S.
-spec mcs_state(server()) -> #mcs_state{}.
mcs_state({_, #state{mcs = S}}) -> S.
-spec get_tsuds(server()) -> [client_tsud()].
get_tsuds({_, #state{tsuds = Ts}}) -> Ts.
-spec get_caps(server()) -> [ts_cap()].
get_caps({_, #state{caps = Cs}}) -> Cs.

-spec send_raw(server(), binary()) -> ok | {error, term()}.
send_raw(Srv, Bin) ->
    send_raw2(curstate(Srv), Bin).
send_raw2(#state{sslsock = none, sock = Sock}, Bin) ->
    gen_tcp:send(Sock, Bin);
send_raw2(#state{sslsock = Sock}, Bin) ->
    ssl:send(Sock, Bin).

-spec send(server(), tuple()) -> ok | {error, term()}.
send({Pid, #state{sslsock = Sock}}, McsPkt) ->
    {ok, McsData} = mcsgcc:encode_dpdu(McsPkt),
    {ok, DtData} = x224:encode(#x224_dt{data = McsData}),
    {ok, Packet} = tpkt:encode(DtData),
    case self() of
        Pid -> ssl:send(Sock, Packet);
        _ -> gen_fsm:sync_send_event(Pid, {send, Packet})
    end.

% only for raw_mode
-spec start_tls(server(), [term()], #x224_cc{}) -> ok.
start_tls({Pid, #state{}}, SslOpts, CC = #x224_cc{}) ->
    {ok, Data} = x224:encode(CC),
    {ok, Packet} = tpkt:encode(Data),
    gen_fsm:send_event(Pid, {start_tls, SslOpts, Packet}).

-spec send_update(server(), tuple()) -> ok | {error, term()}.
send_update(S = {Pid, State = #state{sslsock = SslSock, caps = Caps}}, TsUpdate) ->
    #ts_cap_general{flags = Flags} = lists:keyfind(ts_cap_general, 1, Caps),
    case lists:member(fastpath, Flags) of
        true ->
            Bin = fastpath:encode_output(#fp_pdu{flags=[salted_mac], contents=[TsUpdate]}),
            case self() of
                Pid -> ssl:send(SslSock, Bin);
                _ -> gen_fsm:sync_send_event(Pid, {send, Bin})
            end;
        _ ->
            #state{shareid = ShareId, mcs = #mcs_state{us = Us, iochan = IoChan}} = State,
            {ok, Bin} = rdpp:encode_sharecontrol(#ts_sharedata{channel = Us, shareid = ShareId, data = TsUpdate}),
            send(S, #mcs_srv_data{user = Us, channel = IoChan, data = Bin})
    end.

curstate({Pid, State0}) ->
    case self() of
        Pid -> State0;
        _ ->
            {ok, State1} = gen_fsm:sync_send_all_state_event(Pid, get_state),
            State1
    end.

-spec get_canvas(server()) -> {Width :: integer(), Height :: integer(), Bpp :: integer()}.
get_canvas(Srv) ->
    #state{caps = Caps, bpp = Bpp} = curstate(Srv),
    #ts_cap_bitmap{width = W, height = H} = lists:keyfind(ts_cap_bitmap, 1, Caps),
    {W, H, Bpp}.

-spec get_redir_support(server()) -> true | false.
get_redir_support(Srv) ->
    #state{tsuds = Tsuds} = curstate(Srv),
    case lists:keyfind(tsud_cluster, 1, Tsuds) of
        #tsud_cluster{flags = Flags, version = V} when V >= 4 ->
            lists:member(supported, Flags);
        _ ->
            false
    end.

-spec get_autologon(server()) -> {true | false, Username :: binary(), Domain :: binary(), Password :: binary()}.
get_autologon(Srv) ->
    #state{client_info = TsInfo} = curstate(Srv),
    #ts_info{flags = Flags, username = U0, domain = Do0, password = P0} = TsInfo,
    Unicode = lists:member(unicode, Flags),
    NullLen = if Unicode -> 2; not Unicode -> 1 end,
    U1 = binary:part(U0, {0, byte_size(U0) - NullLen}),
    Do1 = binary:part(Do0, {0, byte_size(Do0) - NullLen}),
    P1 = binary:part(P0, {0, byte_size(P0) - NullLen}),
    U2 = if Unicode -> unicode:characters_to_binary(U1, {utf16,little}, utf8); not Unicode -> U1 end,
    [U3 | _] = binary:split(U2, <<0>>),
    Do2 = if Unicode -> unicode:characters_to_binary(Do1, {utf16,little}, utf8); not Unicode -> Do1 end,
    [Do3 | _] = binary:split(Do2, <<0>>),
    P2 = if Unicode -> unicode:characters_to_binary(P1, {utf16,little}, utf8); not Unicode -> P1 end,
    [P3 | _] = binary:split(P2, <<0>>),
    {lists:member(autologon, Flags), U3, Do3, P3}.

-spec send_redirect(server(), Cookie :: binary(), Hostname :: binary()) -> ok | {error, term()}.
send_redirect({Pid, _}, Cookie, Hostname) ->
    gen_fsm:send_event(Pid, {send_redirect, Cookie, Hostname}).

-spec watch_child(server(), pid()) -> ok.
watch_child({Pid, _}, Kid) ->
    gen_fsm:send_all_state_event(Pid, {watch_child, Kid}).

-spec close(server()) -> ok.
close({Pid, _}) ->
    gen_fsm:send_event(Pid, close).
