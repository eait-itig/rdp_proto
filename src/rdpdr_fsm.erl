%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2022 Alex Wilson <alex@uq.edu.au>
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

-module(rdpdr_fsm).

-compile([{parse_transform, lager_transform}]).

-behaviour(gen_statem).
-behaviour(rdp_vchan_fsm).

-include("rdpp.hrl").
-include("mcsgcc.hrl").
-include("rdpdr.hrl").

-export([
    start_link/2,
    handle_pdu/2,
    get_devices/1,
    open/5,
    ioctl/4
    ]).

-export([
    init/1,
    terminate/3,
    callback_mode/0
    ]).
-export([
    startup/3,
    client_name/3,
    caps_exchange/3,
    await_devices/3,
    running/3,
    broken/3
    ]).

-spec start_link(rdp_server:server(), mcs_chan()) -> {ok, pid()} | {error, term()}.
start_link(Srv, VChanId) ->
    gen_statem:start_link(?MODULE, [Srv, VChanId], []).

-spec handle_pdu(pid(), #ts_vchan{}) -> ok | {error, term()}.
handle_pdu(Pid, VPdu) ->
    gen_statem:cast(Pid, {vpdu, VPdu}).

-spec get_devices(pid()) -> {ok, [rdpdr:dev()]} | {error, term()}.
get_devices(Pid) ->
    gen_statem:call(Pid, get_devices).

-spec open(pid(), rdpdr:dev_id(), string(), rdpdr:access_mode(),
    rdpdr:create_dispos()) -> {ok, rdpdr:file_id()} | {error, term()}.
open(Pid, DevId, Path, Access, Dispos) ->
    gen_statem:call(Pid, {open, DevId, Path, Access, Dispos}).

-spec ioctl(pid(), rdpdr:dev_id(), integer(), binary()) ->
    {ok, binary()} | {error, term()}.
ioctl(Pid, DevId, Cmd, InputData) ->
    gen_statem:call(Pid, {ioctl, DevId, Cmd, InputData}).

-type devid() :: integer().
-type fileid() :: integer().
-type reqid() :: integer().

-record(?MODULE, {
    srv :: rdp_server:server(),
    chanid :: integer(),
    clientid :: integer(),
    cname :: string(),
    caps :: [rdpdr:cap()],
    devs = #{} :: #{rdpdr:dev_id() => rdpdr:dev()},
    reqs = #{} :: #{rdpdr:req_id() => {rdpdr:req(), gen_statem:from()}},
    files = #{} :: #{rdpdr:file_id() =>
                        {rdpdr:dev_id(), string(), rdpdr:access_mode()}}
    }).

callback_mode() -> [state_functions, state_enter].

init([Srv, ChanId]) ->
    {ok, startup, #?MODULE{srv = Srv, chanid = ChanId}}.

terminate(_Reason, _State, #?MODULE{}) ->
    ok.

startup(enter, _PrevState, #?MODULE{srv = Srv, chanid = ChanId}) ->
    AnnData = rdpdr:encode(#rdpdr_srv_announce{}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last],
        data = AnnData
    }),
    {keep_state_and_data, [{state_timeout, 1000, timeout}]};

startup({call, _}, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]};

startup(cast, {pdu, #rdpdr_clientid_confirm{clientid = CID}},
                                                            S0 = #?MODULE{}) ->
    S1 = S0#?MODULE{clientid = CID},
    {next_state, client_name, S1};

startup(state_timeout, timeout, S0 = #?MODULE{}) ->
    {next_state, broken, S0};

startup(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    decode_vpdu(VPdu, S0).

broken(enter, _PrevState, #?MODULE{}) ->
    {keep_state_and_data, [{state_timeout, 5000, retry}]};

broken({call, From}, _Msg, #?MODULE{}) ->
    gen_statem:reply(From, {error, rdpdr_init_timeout}),
    keep_state_and_data;

broken(state_timeout, retry, S0 = #?MODULE{}) ->
    {next_state, startup, S0};

broken(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    {keep_state_and_data, [postpone]}.

client_name(enter, _PrevState, _S0 = #?MODULE{}) ->
    keep_state_and_data;

client_name({call, _}, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]};

client_name(cast, {pdu, Pdu = #rdpdr_client_name_req{}}, S0 = #?MODULE{}) ->
    {next_state, caps_exchange, S0, [postpone]};

client_name(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    decode_vpdu(VPdu, S0).

caps_exchange(enter, _PrevState, #?MODULE{srv = Srv, chanid = ChanId}) ->
    Caps = [
        #rdpdr_cap_general{specials = 8},
        #rdpdr_cap_smartcard{}
    ],
    CapData = rdpdr:encode(#rdpdr_server_caps{caps = Caps}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last],
        data = CapData
    }),
    keep_state_and_data;

caps_exchange({call, _}, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]};

caps_exchange(cast, {pdu, #rdpdr_clientid_confirm{}}, S0 = #?MODULE{}) ->
    keep_state_and_data;

caps_exchange(cast, {pdu, #rdpdr_client_caps{caps = Caps}}, S0 = #?MODULE{}) ->
    S1 = S0#?MODULE{caps = Caps},
    {next_state, await_devices, S1};

caps_exchange(cast, {pdu, #rdpdr_device_announce{}}, S0 = #?MODULE{}) ->
    {keep_state, S0, [postpone]};

caps_exchange(cast, {pdu, #rdpdr_client_name_req{name = ClientName}},
                                S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    #?MODULE{clientid = CID} = S0,
    S1 = S0#?MODULE{cname = ClientName},
    ConfirmData = rdpdr:encode(#rdpdr_clientid_confirm{clientid = CID}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last],
        data = ConfirmData
    }),
    {keep_state, S1};

caps_exchange(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    decode_vpdu(VPdu, S0).

await_devices(enter, _PrevState, S0 = #?MODULE{}) ->
    % other side might not send any devices if they don't have any
    % after a little wait, we will just start to process requests anyway
    % (any late ones will get processed in running)
    {keep_state_and_data, [{state_timeout, 500, timeout}]};

await_devices({call, _}, _, #?MODULE{}) ->
    {keep_state_and_data, [postpone]};

await_devices(cast, {pdu, #rdpdr_device_announce{devices = Devs}},
                                S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    {Replies, DevMap} = lists:foldl(fun
        (D = #rdpdr_dev_smartcard{id = Id}, {Rep0, Map0}) ->
            Rep1 = [#rdpdr_device_reply{id = Id,
                status = ntstatus:code_to_int('STATUS_SUCCESS')} | Rep0],
            Map1 = Map0#{Id => D},
            {Rep1, Map1};
        (D, {Rep0, Map0}) when is_tuple(D) and is_atom(element(1,D)) ->
            Rep1 = [#rdpdr_device_reply{id = element(2,D),
                status = ntstatus:code_to_int('STATUS_BAD_FILE_TYPE')} | Rep0],
            {Rep1, Map0}
    end, {[], #{}}, Devs),
    lists:foreach(fun (Reply) ->
        RepData = rdpdr:encode(Reply),
        ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
            flags = [first, last],
            data = RepData
        })
    end, lists:reverse(Replies)),
    {next_state, running, S0#?MODULE{devs = DevMap}};

await_devices(state_timeout, timeout, S0 = #?MODULE{}) ->
    lager:debug("no devices in >1s, probably none coming"),
    {next_state, running, S0};

await_devices(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    decode_vpdu(VPdu, S0).

running(enter, _PrevState, #?MODULE{devs = DevMap}) ->
    lager:debug("rdpdr: devices = ~s", [rdpdr:pretty_print(DevMap)]),
    keep_state_and_data;

running({call, From}, get_devices, S0 = #?MODULE{devs = Devs}) ->
    gen_statem:reply(From, {ok, maps:values(Devs)}),
    keep_state_and_data;

running({call, From}, {open, DevId, Path, Access, Dispos}, S0 = #?MODULE{}) ->
    #?MODULE{devs = Devs, reqs = Reqs0} = S0,
    #{DevId := _Dev} = Devs,
    ReqId = next_req_id(Reqs0),
    Req = #rdpdr_open_req{
        io = #rdpdr_io{device_id = DevId, req_id = ReqId},
        path = Path,
        access = Access,
        dispos = Dispos,
        alloc_size = 65536,
        share = [],
        flags = [],
        attrs = []
    },
    ReqData = rdpdr:encode(Req),
    #?MODULE{srv = Srv, chanid = ChanId} = S0,
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last],
        data = ReqData
    }),
    Reqs1 = Reqs0#{ReqId => {From, Req}},
    {keep_state, S0#?MODULE{reqs = Reqs1}};

running(cast, {io, From, Req, Resp = #rdpdr_open_resp{}}, S0 = #?MODULE{files = F0}) ->
    #rdpdr_open_resp{file_id = FileId, io = IO} = Resp,
    #rdpdr_io{device_id = DevId} = IO,
    gen_statem:reply(From, {ok, FileId}),
    #rdpdr_open_req{path = Path, access = Access} = Req,
    F1 = F0#{FileId => {DevId, Path, Access}},
    {keep_state, S0#?MODULE{files = F1}};

running({call, From}, {ioctl, DevId, Cmd, InData}, S0 = #?MODULE{}) ->
    #?MODULE{devs = Devs, reqs = Reqs0} = S0,
    #{DevId := _Dev} = Devs,
    ReqId = next_req_id(Reqs0),
    Req = #rdpdr_control_req{
        io = #rdpdr_io{device_id = DevId, req_id = ReqId, file_id = 0},
        code = Cmd,
        expect_len = 65536,
        data = InData
    },
    %lager:debug("rdpdr => ~s", [rdpdr:pretty_print(Req)]),
    ReqData = rdpdr:encode(Req),
    #?MODULE{srv = Srv, chanid = ChanId} = S0,
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last],
        data = ReqData
    }),
    Reqs1 = Reqs0#{ReqId => {From, Req}},
    {keep_state, S0#?MODULE{reqs = Reqs1}};

running(cast, {io, From, Req, Resp = #rdpdr_control_resp{}}, S0 = #?MODULE{}) ->
    #rdpdr_control_resp{data = OutData, io = IO} = Resp,
    gen_statem:reply(From, {ok, OutData}),
    {keep_state, S0};

running(cast, {pdu, R = #rdpdr_io_resp{io = IO}}, S0 = #?MODULE{reqs = Reqs0}) ->
    #rdpdr_io{req_id = ReqId} = IO,
    case Reqs0 of
        #{ReqId := {From, Req}} ->
            Reqs1 = maps:remove(ReqId, Reqs0),
            S1 = S0#?MODULE{reqs = Reqs1},
            case R of
                #rdpdr_io_resp{status = {success, _}} ->
                    case rdpdr:decode(R, Req) of
                        {ok, Resp} ->
                            %lager:debug("rdpdr: ~s", [rdpdr:pretty_print(Resp)]),
                            {keep_state, S1, [
                                {next_event, cast, {io, From, Req, Resp}}]};
                        Err ->
                            %lager:debug("rdpdr decode fail on io resp (~B): "
                            %    "~p: ~s", [ReqId, Err, rdpdr:pretty_print(R)]),
                            {keep_state, S1}
                    end;
                #rdpdr_io_resp{status = Err} ->
                    gen_statem:reply(From, {error, Err}),
                    {keep_state, S1}
            end;
        _ ->
            lager:debug("rdpdr unsolicited resp: ~s", [rdpdr:pretty_print(R)]),
            keep_state_and_data
    end;

running(cast, {pdu, #rdpdr_device_announce{devices = Devs}},
                                S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    #?MODULE{devs = DevMap0} = S0,
    {Replies, DevMap1} = lists:foldl(fun
        (D = #rdpdr_dev_smartcard{id = Id}, {Rep0, Map0}) ->
            Rep1 = [#rdpdr_device_reply{id = Id,
                status = ntstatus:code_to_int('STATUS_SUCCESS')} | Rep0],
            Map1 = Map0#{Id => D},
            {Rep1, Map1};
        (D, {Rep0, Map0}) when is_tuple(D) and is_atom(element(1,D)) ->
            Rep1 = [#rdpdr_device_reply{id = element(2,D),
                status = ntstatus:code_to_int('STATUS_BAD_FILE_TYPE')} | Rep0],
            {Rep1, Map0}
    end, {[], DevMap0}, Devs),
    lists:foreach(fun (Reply) ->
        RepData = rdpdr:encode(Reply),
        ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
            flags = [first, last],
            data = RepData
        })
    end, lists:reverse(Replies)),
    {keep_state, S0#?MODULE{devs = DevMap1}};

running(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    decode_vpdu(VPdu, S0).

next_req_id(Reqs) -> next_req_id(0, Reqs).
next_req_id(N, Reqs) ->
    case Reqs of
        #{N := _} ->
            next_req_id(N + 1, Reqs);
        _ ->
            N
    end.

decode_vpdu(VPdu = #ts_vchan{flags = _Fl, data = D}, #?MODULE{}) ->
    case (catch rdpdr:decode(D)) of
        {'EXIT', Why} ->
            lager:debug("rdpdr decode fail: ~p (~s)", [Why, rdpp:pretty_print(VPdu)]),
            keep_state_and_data;
        {ok, ClipPdu} ->
            %lager:debug("rdpdr: ~s", [rdpdr:pretty_print(ClipPdu)]),
            {keep_state_and_data, [{next_event, cast, {pdu, ClipPdu}}]};
        Err ->
            lager:debug("rdpdr decode fail: ~p (~s)", [Err, rdpp:pretty_print(VPdu)]),
            keep_state_and_data
    end.
