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

-module(rdpdr_scard).

-export([
    open/3,
    close/1,
    list_groups/1,
    list_readers/2,
    connect/4,
    disconnect/2,
    begin_txn/1,
    end_txn/2,
    transceive/2,
    reconnect/4,
    reconnect/2
    ]).

-export_type([
    state/0
    ]).

-export([
    pretty_print/1
    ]).

-compile([{parse_transform, bitset_parse_transform}]).
-compile([{parse_transform, msrpce_parse_transform}]).
-compile([{parse_transform, lager_transform}]).

-include_lib("msrpce/include/records.hrl").
-include_lib("msrpce/include/types.hrl").

-type scard_scope() :: msrpce:custom(ulong(), user | terminal | system,
    encode_scard_scope, decode_scard_scope).

-type unicode_msz_in_bytes() :: msrpce:custom(varying_bin(),
    [string()], encode_umsz_bytes, decode_umsz_bytes).

-type long_boolean() :: msrpce:custom(ulong(), boolean(),
    encode_long_bool, decode_long_bool).

-type len_or_auto() :: msrpce:custom(ulong(), auto | integer(),
    encode_len_or_auto, decode_len_or_auto).

-type share_mode() :: msrpce:custom(ulong(), exclusive | shared | direct,
    encode_share_mode, decode_share_mode).

-type protocol_id() :: msrpce:custom(ulong(),
    {undefined | t0 | t1 | t0_or_t1 | raw, default | optimal},
    encode_proto_id, decode_proto_id).

-type disposition() :: msrpce:custom(ulong(),
    leave | reset | unpower | eject,
    encode_dispos, decode_dispos).

-type apdu() :: binary().

-define(SCARD_IOCTL_ESTABLISHCONTEXT,   16#00090014).
-define(SCARD_IOCTL_RELEASECONTEXT,     16#00090018).
-define(SCARD_IOCTL_LISTREADERSW,       16#0009002C).
-define(SCARD_IOCTL_LISTGROUPSW,        16#00090024).
-define(SCARD_IOCTL_CONNECTW,           16#000900B0).
-define(SCARD_IOCTL_DISCONNECT,         16#000900B8).
-define(SCARD_IOCTL_BEGINTRANSACTION,   16#000900BC).
-define(SCARD_IOCTL_ENDTRANSACTION,     16#000900C0).
-define(SCARD_IOCTL_TRANSMIT,           16#000900D0).
-define(SCARD_IOCTL_RECONNECT,          16#000900B4).

-record(redir_scardcontext, {
    len :: size_of(ctx, ulong()),
    ctx :: pointer(varying_bin())
    }).

-record(redir_scardhandle, {
    ctx :: #redir_scardcontext{},
    len :: size_of(hdl, ulong()),
    hdl :: pointer(varying_bin())
    }).

-record(context_call, {
    ctx :: #redir_scardcontext{}
    }).

-record(long_return, {
    code :: ulong()
    }).

-record(establish_context_call, {
    scope :: scard_scope()
    }).

-record(establish_context_return, {
    code :: ulong(),
    ctx :: #redir_scardcontext{}
    }).

-record(list_groups_call, {
    ctx :: #redir_scardcontext{},
    len_only :: long_boolean(),
    expect_len :: len_or_auto()
    }).

-record(list_groups_return, {
    code :: ulong(),
    len :: size_of(groups, ulong()),
    groups :: pointer(unicode_msz_in_bytes())
    }).

-record(list_readers_call, {
    ctx :: #redir_scardcontext{},
    len :: size_of(groups, ulong()),
    groups :: pointer(unicode_msz_in_bytes()),
    len_only :: long_boolean(),
    expect_len :: len_or_auto()
    }).

-record(list_readers_return, {
    code :: ulong(),
    len :: size_of(readers, ulong()),
    readers :: pointer(unicode_msz_in_bytes())
    }).

-record(connect_common, {
    ctx :: #redir_scardcontext{},
    share_mode :: share_mode(),
    pref_protos :: protocol_id()
    }).

-record(connect_call, {
    reader :: pointer(unicode()),
    common :: #connect_common{}
    }).

-record(connect_return, {
    code :: ulong(),
    handle :: #redir_scardhandle{},
    proto :: protocol_id()
    }).

-record(reconnect_call, {
    handle :: #redir_scardhandle{},
    share_mode :: share_mode(),
    pref_protos :: protocol_id(),
    init :: disposition()
    }).

-record(reconnect_return, {
    code :: ulong(),
    proto :: protocol_id()
    }).

-record(hcard_and_dispos_call, {
    handle :: #redir_scardhandle{},
    dispos :: disposition()
    }).

-record(scardio_request, {
    proto :: protocol_id(),
    extralen :: size_of(extra, ulong()),
    extra = undefined :: pointer(varying_bin())
    }).

-record(transmit_call, {
    handle :: #redir_scardhandle{},
    send_pci :: #scardio_request{},
    len :: size_of(data, ulong()),
    data :: pointer(varying_bin()),
    recv_pci = undefined :: pointer(#scardio_request{}),
    len_only = false :: long_boolean(),
    recv_len = 1024 :: ulong()
    }).

-record(transmit_return, {
    code :: ulong(),
    recv_pci :: pointer(#scardio_request{}),
    len :: size_of(data, ulong()),
    data :: pointer(varying_bin())
    }).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(redir_scardcontext);
?pp(redir_scardhandle);
?pp(context_call);
?pp(long_return);
?pp(establish_context_call);
?pp(establish_context_return);
?pp(list_groups_call);
?pp(list_groups_return);
?pp(list_readers_call);
?pp(list_readers_return);
?pp(connect_common);
?pp(connect_call);
?pp(connect_return);
?pp(hcard_and_dispos_call);
?pp(scardio_request);
?pp(transmit_call);
?pp(transmit_return);
pretty_print(_, _) ->
    no.

encode_scard_scope(user) -> 0;
encode_scard_scope(terminal) -> 1;
encode_scard_scope(system) -> 2.
decode_scard_scope(0) -> user;
decode_scard_scope(1) -> terminal;
decode_scard_scope(2) -> system.

encode_long_bool(true) -> 1;
encode_long_bool(false) -> 0.
decode_long_bool(0) -> false;
decode_long_bool(1) -> true.

encode_len_or_auto(auto) -> 16#FFFFFFFF;
encode_len_or_auto(Len) when is_integer(Len) -> Len.
decode_len_or_auto(16#FFFFFFFF) -> auto;
decode_len_or_auto(Len) -> Len.

encode_umsz_bytes(undefined) -> undefined;
encode_umsz_bytes(Strings) ->
    Joined = lists:flatten(lists:join(0, Strings) ++ [0,0]),
    unicode:characters_to_binary(Joined, utf8, {utf16, little}).
decode_umsz_bytes(undefined) -> undefined;
decode_umsz_bytes(Bin) ->
    Arr = unicode:characters_to_list(Bin, {utf16, little}),
    string:lexemes(Arr, [0]).

encode_proto_id({Tpdu, Params}) ->
    V0 = case Tpdu of
        undefined -> 16#00000000;
        t0        -> 16#00000001;
        t1        -> 16#00000002;
        t0_or_t1  -> 16#00000003;
        raw       -> 16#00010000
    end,
    V0 bor (case Params of
        default   -> 16#80000000;
        optimal   -> 16#00000000
    end).
decode_proto_id(V) ->
    Params = case (V band 16#80000000) of
        0 -> optimal;
        _ -> default
    end,
    Tpdu = case (V band 16#00010003) of
        16#00010000 -> raw;
        16#00000002 -> t1;
        16#00000001 -> t0;
        16#00000003 -> t0_or_t1;
        16#00000000 -> undefined
    end,
    {Tpdu, Params}.

encode_share_mode(exclusive) -> 1;
encode_share_mode(shared) -> 2;
encode_share_mode(direct) -> 3.
decode_share_mode(1) -> exclusive;
decode_share_mode(2) -> shared;
decode_share_mode(3) -> direct.

encode_dispos(leave) -> 0;
encode_dispos(reset) -> 1;
encode_dispos(unpower) -> 2;
encode_dispos(eject) -> 3.
decode_dispos(0) -> leave;
decode_dispos(1) -> reset;
decode_dispos(2) -> unpower;
decode_dispos(3) -> eject.

-rpce(#{endian => little}).
-rpce_stream({req_context, [context_call]}).
-rpce_stream({resp_long, [long_return]}).
-rpce_stream({req_establish_context, [establish_context_call]}).
-rpce_stream({resp_establish_context, [establish_context_return]}).
-rpce_stream({req_list_groups, [list_groups_call]}).
-rpce_stream({resp_list_groups, [list_groups_return]}).
-rpce_stream({req_list_readers, [list_readers_call]}).
-rpce_stream({resp_list_readers, [list_readers_return]}).
-rpce_stream({req_connect, [connect_call]}).
-rpce_stream({resp_connect, [connect_return]}).
-rpce_stream({req_hcard_and_dispos, [hcard_and_dispos_call]}).
-rpce_stream({req_transmit, [transmit_call]}).
-rpce_stream({resp_transmit, [transmit_return]}).
-rpce_stream({req_reconnect, [reconnect_call]}).
-rpce_stream({resp_reconnect, [reconnect_return]}).

-record(?MODULE, {
    rdpdr :: pid(),
    devid :: rdpdr:dev_id(),
    scope :: scard_scope(),
    ctx :: #redir_scardcontext{},
    hdl :: undefined | #redir_scardhandle{},
    proto :: undefined | protocol_id(),
    share_mode :: undefined | share_mode(),
    req_proto :: undefined | protocol_id()
    }).

-opaque state() :: #?MODULE{}.

do_ioctl(IOC, Rec, Encoder, Decoder, #?MODULE{rdpdr = Pid, devid = DevId}) ->
    %lager:debug("=> ~s", [pretty_print(Rec)]),
    InData = Encoder([Rec]),
    R = rdpdr_fsm:ioctl(Pid, DevId, IOC, InData),
    case R of
        {ok, OutData} ->
            case (catch Decoder(OutData)) of
                {'EXIT', Why} ->
                    {error, Why};
                [OutRec] ->
                    %lager:debug("<= ~s", [pretty_print(OutRec)]),
                    {ok, OutRec}
            end;
        Err ->
            %lager:debug("<= ~p", [Err]),
            Err
    end.

-spec open(pid(), rdpdr:dev_id(), scard_scope()) -> {ok, state()} | {error, term()}.
open(Pid, DevId, Scope) ->
    Call = #establish_context_call{scope = Scope},
    IOC = ?SCARD_IOCTL_ESTABLISHCONTEXT,
    Enc = fun encode_req_establish_context/1,
    Dec = fun decode_resp_establish_context/1,
    S = #?MODULE{rdpdr = Pid, devid = DevId},
    case do_ioctl(IOC, Call, Enc, Dec, S) of
        {ok, #establish_context_return{code = 0, ctx = Ctx}} ->
            {ok, #?MODULE{rdpdr = Pid, devid = DevId, scope = Scope,
                          ctx = Ctx}};
        {ok, #establish_context_return{code = ErrCode}} ->
            {error, {scard, scard_err_to_atom(ErrCode)}};
        Err ->
            Err
    end.

-spec close(state()) -> ok | {error, term()}.
close(S0 = #?MODULE{ctx = Ctx, hdl = undefined}) ->
    Call = #context_call{ctx = Ctx},
    IOC = ?SCARD_IOCTL_RELEASECONTEXT,
    Enc = fun encode_req_context/1,
    Dec = fun decode_resp_long/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #long_return{code = _Code}} -> ok;
        Err -> Err
    end.

-spec list_groups(state()) -> {ok, [string()], state()} | {error, term()}.
list_groups(S0 = #?MODULE{ctx = Ctx}) ->
    Call = #list_groups_call{ctx = Ctx, len_only = false, expect_len = auto},
    IOC = ?SCARD_IOCTL_LISTGROUPSW,
    Enc = fun encode_req_list_groups/1,
    Dec = fun decode_resp_list_groups/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #list_groups_return{code = 0, groups = Groups}} ->
            {ok, Groups, S0};
        {ok, #list_groups_return{code = ErrCode}} ->
            {error, {scard, scard_err_to_atom(ErrCode)}};
        Err ->
            Err
    end.

-spec list_readers(string(), state()) -> {ok, [string()], state()} | {error, term()}.
list_readers(Group, S0 = #?MODULE{ctx = Ctx}) ->
    Call = #list_readers_call{ctx = Ctx, len_only = false, expect_len = auto,
        groups = [Group]},
    IOC = ?SCARD_IOCTL_LISTREADERSW,
    Enc = fun encode_req_list_readers/1,
    Dec = fun decode_resp_list_readers/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #list_readers_return{code = 0, readers = undefined, len = Len}} ->
            % Despite the fact that we asked for it to auto-allocate, it's given
            % us an explicit length... try again, I guess!
            Call2 = Call#list_readers_call{expect_len = Len},
            case do_ioctl(IOC, Call2, Enc, Dec, S0) of
                {ok, #list_readers_return{code = 0, readers = Readers}} ->
                    {ok, Readers, S0};
                {ok, #list_readers_return{code = ErrCode}} ->
                    {error, {scard, ErrCode}};
                Err ->
                    Err
            end;
        {ok, #list_readers_return{code = 0, readers = Readers}} ->
            {ok, Readers, S0};
        {ok, #list_readers_return{code = ErrCode}} ->
            {error, {scard, ErrCode}};
        Err ->
            Err
    end.

-spec connect(string(), share_mode(), protocol_id(), state()) ->
    {ok, protocol_id(), state()} | {error, term()}.
connect(Reader, ShareMode, ProtoId, S0 = #?MODULE{ctx = Ctx, hdl = undefined}) ->
    Common = #connect_common{ctx = Ctx, share_mode = ShareMode,
                             pref_protos = ProtoId},
    Call = #connect_call{reader = Reader ++ [0], common = Common},
    IOC = ?SCARD_IOCTL_CONNECTW,
    Enc = fun encode_req_connect/1,
    Dec = fun decode_resp_connect/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #connect_return{code = 0, handle = Hdl0, proto = Proto}} ->
            Hdl1 = Hdl0#redir_scardhandle{ctx = Ctx},
            S1 = S0#?MODULE{hdl = Hdl1, proto = Proto, req_proto = ProtoId,
                            share_mode = ShareMode},
            {ok, Proto, S1};
        {ok, #connect_return{code = ErrCode}} ->
            {error, {scard, scard_err_to_atom(ErrCode)}};
        Err ->
            Err
    end.

-spec reconnect(disposition(), state()) -> {ok, protocol_id(), state()} |
    {error, term()}.
reconnect(Dispos, S0 = #?MODULE{hdl = Hdl, req_proto = ProtoId,
                                share_mode = ShareMode}) when not (Hdl =:= undefined) ->
    reconnect(ShareMode, ProtoId, Dispos, S0).

-spec reconnect(share_mode(), protocol_id(), disposition(), state()) ->
    {ok, protocol_id(), state()} | {error, term()}.
reconnect(ShareMode, ProtoId, Dispos, S0 = #?MODULE{hdl = Hdl})
                                            when not (Hdl =:= undefined) ->
    Call = #reconnect_call{handle = Hdl, share_mode = ShareMode,
                           pref_protos = ProtoId, init = Dispos},
    IOC = ?SCARD_IOCTL_RECONNECT,
    Enc = fun encode_req_reconnect/1,
    Dec = fun decode_resp_reconnect/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #reconnect_return{code = 0, proto = Proto}} ->
            S1 = S0#?MODULE{proto = Proto},
            {ok, Proto, S1};
        {ok, #reconnect_return{code = ErrCode}} ->
            {error, {scard, scard_err_to_atom(ErrCode)}};
        Err ->
            Err
    end.

-spec disconnect(disposition(), state()) -> {ok, state()} | {error, term()}.
disconnect(Dispos, S0 = #?MODULE{hdl = Hdl}) when not (Hdl =:= undefined) ->
    Call = #hcard_and_dispos_call{handle = Hdl, dispos = Dispos},
    IOC = ?SCARD_IOCTL_DISCONNECT,
    Enc = fun encode_req_hcard_and_dispos/1,
    Dec = fun decode_resp_long/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #long_return{code = 0}} ->
            S1 = S0#?MODULE{hdl = undefined},
            {ok, S1};
        {ok, #long_return{code = ErrCode}} ->
            {error, {scard, scard_err_to_atom(ErrCode)}};
        Err ->
            Err
    end.

-spec begin_txn(state()) -> {ok, state()} | {error, term()}.
begin_txn(S0 = #?MODULE{hdl = Hdl}) when not (Hdl =:= undefined) ->
    Call = #hcard_and_dispos_call{handle = Hdl, dispos = leave},
    IOC = ?SCARD_IOCTL_BEGINTRANSACTION,
    Enc = fun encode_req_hcard_and_dispos/1,
    Dec = fun decode_resp_long/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #long_return{code = 0}} ->
            {ok, S0};
        {ok, #long_return{code = ErrCode}} ->
            {error, {scard, scard_err_to_atom(ErrCode)}};
        Err ->
            Err
    end.

-spec end_txn(disposition(), state()) -> {ok, state()} | {error, term()}.
end_txn(Dispos, S0 = #?MODULE{hdl = Hdl}) when not (Hdl =:= undefined) ->
    Call = #hcard_and_dispos_call{handle = Hdl, dispos = Dispos},
    IOC = ?SCARD_IOCTL_ENDTRANSACTION,
    Enc = fun encode_req_hcard_and_dispos/1,
    Dec = fun decode_resp_long/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #long_return{code = 0}} ->
            {ok, S0};
        {ok, #long_return{code = ErrCode}} ->
            {error, {scard, scard_err_to_atom(ErrCode)}};
        Err ->
            Err
    end.

-spec transceive(apdu(), state()) -> {ok, apdu(), state()} | {error, term()}.
transceive(DataIn, S0 = #?MODULE{hdl = Hdl}) when not (Hdl =:= undefined) ->
    #?MODULE{proto = Proto} = S0,
    SendPCI = #scardio_request{proto = Proto},
    Call = #transmit_call{handle = Hdl,
                          send_pci = SendPCI,
                          data = DataIn},
    IOC = ?SCARD_IOCTL_TRANSMIT,
    Enc = fun encode_req_transmit/1,
    Dec = fun decode_resp_transmit/1,
    case do_ioctl(IOC, Call, Enc, Dec, S0) of
        {ok, #transmit_return{code = 0, data = DataOut}} ->
            {ok, DataOut, S0};
        {ok, #transmit_return{code = ErrCode}} ->
            {error, {scard, scard_err_to_atom(ErrCode)}};
        Err ->
            Err
    end.

scard_err_to_atom(16#00000000) -> success;
scard_err_to_atom(16#80100001) -> internal_error;
scard_err_to_atom(16#80100002) -> cancelled;
scard_err_to_atom(16#80100003) -> invalid_handle;
scard_err_to_atom(16#80100004) -> invalid_parameter;
scard_err_to_atom(16#80100005) -> invalid_target;
scard_err_to_atom(16#80100006) -> no_memory;
scard_err_to_atom(16#80100007) -> waited_too_long;
scard_err_to_atom(16#80100008) -> insufficient_buffer;
scard_err_to_atom(16#80100009) -> unknown_reader;
scard_err_to_atom(16#8010000A) -> timeout;
scard_err_to_atom(16#8010000B) -> sharing_violation;
scard_err_to_atom(16#8010000C) -> no_smartcard;
scard_err_to_atom(16#8010000D) -> unknown_card;
scard_err_to_atom(16#8010000E) -> cant_dispose;
scard_err_to_atom(16#8010000F) -> proto_mismatch;
scard_err_to_atom(16#80100010) -> not_ready;
scard_err_to_atom(16#80100011) -> invalid_value;
scard_err_to_atom(16#80100012) -> system_cancelled;
scard_err_to_atom(16#80100013) -> comm_error;
scard_err_to_atom(16#80100014) -> unknown_error;
scard_err_to_atom(16#80100015) -> invalid_atr;
scard_err_to_atom(16#80100016) -> not_transacted;
scard_err_to_atom(16#80100017) -> reader_unavailable;
scard_err_to_atom(16#80100019) -> pci_too_small;
scard_err_to_atom(16#8010001A) -> reader_unsupported;
scard_err_to_atom(16#8010001B) -> duplicate_reader;
scard_err_to_atom(16#8010001C) -> card_unsupported;
scard_err_to_atom(16#8010001D) -> no_service;
scard_err_to_atom(16#8010001E) -> service_stopped;
scard_err_to_atom(16#8010001F) -> unsupported_feature;
scard_err_to_atom(16#80100020) -> icc_installation;
scard_err_to_atom(16#80100021) -> icc_createorder;
scard_err_to_atom(16#80100023) -> dir_not_found;
scard_err_to_atom(16#80100024) -> file_not_found;
scard_err_to_atom(16#80100025) -> no_dir;
scard_err_to_atom(16#80100026) -> no_file;
scard_err_to_atom(16#80100027) -> no_access;
scard_err_to_atom(16#80100028) -> write_too_many;
scard_err_to_atom(16#80100029) -> bad_seek;
scard_err_to_atom(16#8010002A) -> invalid_chv;
scard_err_to_atom(16#8010002B) -> unknown_res_mng;
scard_err_to_atom(16#8010002C) -> no_such_certificate;
scard_err_to_atom(16#8010002D) -> certificate_unavailable;
scard_err_to_atom(16#8010002E) -> no_readers_available;
scard_err_to_atom(16#8010002F) -> comm_data_lost;
scard_err_to_atom(16#80100030) -> no_key_container;
scard_err_to_atom(16#80100031) -> server_too_busy;
scard_err_to_atom(16#80100065) -> unsupported_card;
scard_err_to_atom(16#80100066) -> unresponsive_card;
scard_err_to_atom(16#80100067) -> unpowered_card;
scard_err_to_atom(16#80100068) -> reset_card;
scard_err_to_atom(16#80100069) -> removed_card;
scard_err_to_atom(16#8010006A) -> security_violation;
scard_err_to_atom(16#8010006B) -> wrong_chv;
scard_err_to_atom(16#8010006C) -> chv_blocked;
scard_err_to_atom(16#8010006D) -> eof;
scard_err_to_atom(16#8010006E) -> cancelled_by_user;
scard_err_to_atom(16#8010006F) -> card_not_authenticated;
scard_err_to_atom(Other) -> Other.
