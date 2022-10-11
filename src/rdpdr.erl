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

-module(rdpdr).

-include("rdpdr.hrl").

-compile([{parse_transform, bitset_parse_transform}]).

-export([pretty_print/1]).
-export([encode/1, decode/1, decode/2]).

-export_type([cap/0, pdu/0, dev/0, dev_id/0, file_id/0, dev_type/0,
    dos_name/0, req_id/0, cap_flags/0, io_reqs/0, extpdu/0]).
-export_type([req/0, resp/0]).
-export_type([access_mode/0, share_mode/0, create_flags/0, create_dispos/0,
    file_attrs/0]).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(rdpdr_srv_announce);
?pp(rdpdr_clientid_confirm);
?pp(rdpdr_client_name_req);
?pp(rdpdr_server_caps);
?pp(rdpdr_client_caps);
?pp(rdpdr_cap_general);
?pp(rdpdr_cap_printer);
?pp(rdpdr_cap_drive);
?pp(rdpdr_cap_port);
?pp(rdpdr_cap_smartcard);
?pp(rdpdr_device_announce);
?pp(rdpdr_dev_serial);
?pp(rdpdr_dev_parallel);
?pp(rdpdr_dev_printer);
?pp(rdpdr_dev_fs);
?pp(rdpdr_dev_smartcard);
?pp(rdpdr_device_remove);
?pp(rdpdr_io);
?pp(rdpdr_io_resp);
?pp(rdpdr_open_req);
?pp(rdpdr_open_resp);
?pp(rdpdr_close_req);
?pp(rdpdr_close_resp);
?pp(rdpdr_control_req);
?pp(rdpdr_control_resp);
pretty_print(_, _) ->
    no.

-define(RDPDR_CTYP_CORE, 16#4472).
-define(RDPDR_CTYP_PRN, 16#5052).

-define(PAKID_CORE_SERVER_ANNOUNCE,     16#496E).
-define(PAKID_CORE_CLIENTID_CONFIRM,    16#4343).
-define(PAKID_CORE_CLIENT_NAME,         16#434E).
-define(PAKID_CORE_DEVICELIST_ANNOUNCE, 16#4441).
-define(PAKID_CORE_DEVICE_REPLY,        16#6472).
-define(PAKID_CORE_DEVICE_IOREQUEST,    16#4952).
-define(PAKID_CORE_DEVICE_IOCOMPLETION, 16#4943).
-define(PAKID_CORE_SERVER_CAP,          16#5350).
-define(PAKID_CORE_CLIENT_CAP,          16#4350).
-define(PAKID_CORE_DEVICELIST_REMOVE,   16#444D).
-define(PAKID_CORE_USER_LOGGEDON,       16#554C).

-define(CAP_GENERAL_TYPE,   16#0001).
-define(CAP_PRINTER_TYPE,   16#0002).
-define(CAP_PORT_TYPE,      16#0003).
-define(CAP_DRIVE_TYPE,     16#0004).
-define(CAP_SMARTCARD_TYPE, 16#0005).

-define(IRP_MJ_CREATE,          16#00000000).
-define(IRP_MJ_CLOSE,           16#00000002).
-define(IRP_MJ_READ,            16#00000003).
-define(IRP_MJ_WRITE,           16#00000004).
-define(IRP_MJ_DEVICE_CONTROL,  16#0000000e).

-type pdu() :: #rdpdr_srv_announce{} | #rdpdr_clientid_confirm{} |
    #rdpdr_client_name_req{} | #rdpdr_server_caps{} | #rdpdr_client_caps{}.

-type cap() :: #rdpdr_cap_general{} | #rdpdr_cap_printer{} |
    #rdpdr_cap_drive{} | #rdpdr_cap_port{} | #rdpdr_cap_smartcard{}.

-type req() :: #rdpdr_open_req{} | #rdpdr_close_req{}.
-type resp() :: #rdpdr_open_resp{} | #rdpdr_close_resp{}.

-type dev_id() :: integer().
-type file_id() :: integer().
-type req_id() :: integer().

-type dos_name() :: string().

-bitset({access_mode, [
    generic_read, generic_write, generic_exec, generic_all,
    {skip,2}, max_allowed, system_sec,
    {skip,3}, sync,
    write_owner, write_dac, read_ctrl, delete,
    {skip,4},
    {skip,3}, write_attr,
    read_attr, delete_child, exec, write_xattr,
    read_xattr, append, write, read
    ]}).
-bitset({share_mode, [{skip, 29}, delete, write, read]}).
-bitset({create_flags, [
    {skip, 4},
    {skip, 4},
    for_free_space, no_recall, reparse_point, reserve_opfilter,
    {skip, 2}, no_excl, require_oplock,
    no_compress, backup_intent, by_file_id, delete_on_close,
    random, remote_instance, no_xattr, ignore_oplock,
    skip, non_dir_file, sync_io, sync_io_alert,
    no_buffer, sequential, write_through, directory
    ]}).
-bitset({file_attrs, [
    {skip, 8},
    skip, recall_on_access, skip, unpinned,
    pinned, recall_on_open, no_scrub_data, skip,
    integrity_stream, encrypted, no_index, offline,
    compressed, reparse_point, sparse, temporary,
    normal, skip, archive, directory,
    skip, system, hidden, read_only
    ]}).

-type create_dispos() :: supersede | open | create | open_if | overwrite |
    overwrite_if.

-spec encode(pdu()) -> binary() | {error, term()}.

encode(#rdpdr_srv_announce{version = {VerMaj, VerMin}, clientid = ClientId}) ->
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_SERVER_ANNOUNCE:16/little,
      VerMaj:16/little, VerMin:16/little, ClientId:32/little>>;

encode(#rdpdr_clientid_confirm{version = {VerMaj, VerMin}, clientid = ClientId}) ->
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_CLIENTID_CONFIRM:16/little,
      VerMaj:16/little, VerMin:16/little, ClientId:32/little>>;

encode(#rdpdr_client_name_req{unicode = Unicode, name = Name}) ->
    {NameBin, UnicodeFlag} = case Unicode of
        true -> {unicode:characters_to_binary(Name ++ [0], {utf16, little}), 1};
        false -> {unicode:characters_to_binary(Name ++ [0], utf8), 0}
    end,
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_CLIENT_NAME:16/little,
        UnicodeFlag:32/little, 0:32/little, (byte_size(NameBin)):32/little,
        NameBin/binary>>;

encode(#rdpdr_server_caps{caps = Caps}) ->
    CapsBin = iolist_to_binary([encode_cap(Cap) || Cap <- Caps]),
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_SERVER_CAP:16/little,
      (length(Caps)):16/little, 0:16, CapsBin/binary>>;

encode(#rdpdr_client_caps{caps = Caps}) ->
    CapsBin = iolist_to_binary([encode_cap(Cap) || Cap <- Caps]),
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_CLIENT_CAP:16/little,
      (length(Caps)):16/little, 0:16, CapsBin/binary>>;

encode(#rdpdr_device_reply{id = Id, status = Status}) ->
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_DEVICE_REPLY:16/little,
      Id:32/little, Status:32/little>>;

encode(#rdpdr_open_req{io = IO, access = Access, alloc_size = AllocSize,
                       attrs = FileAttrs, share = ShareMode, dispos = Dispos,
                       flags = Flags, path = Path}) ->
    AccessInt = encode_access_mode(Access),
    FileAttrsInt = encode_file_attrs(FileAttrs),
    ShareModeInt = encode_share_mode(ShareMode),
    DisposInt = case Dispos of
        supersede    -> 0;
        open         -> 1;
        create       -> 2;
        open_if      -> 3;
        overwrite    -> 4;
        overwrite_if -> 5
    end,
    FlagsInt = encode_create_flags(Flags),
    PathBin = unicode:characters_to_binary(Path ++ [0], {utf16, little}),
    #rdpdr_io{device_id = DevId, req_id = ReqId, file_id = FileId} = IO,
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_DEVICE_IOREQUEST:16/little,
      DevId:32/little, FileId:32/little, ReqId:32/little,
      ?IRP_MJ_CREATE:32/little, 0:32,
      AccessInt:32/little, AllocSize:64/little, FileAttrsInt:32/little,
      ShareModeInt:32/little, DisposInt:32/little, FlagsInt:32/little,
      (byte_size(PathBin)):32/little, PathBin/binary>>;

encode(#rdpdr_close_req{io = IO}) ->
    #rdpdr_io{device_id = DevId, file_id = FileId, req_id = ReqId} = IO,
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_DEVICE_IOREQUEST:16/little,
      DevId:32/little, FileId:32/little, ReqId:32/little,
      ?IRP_MJ_CLOSE:32/little, 0:32,
      0:32/unit:8>>;

encode(#rdpdr_control_req{io = IO, code = Code, expect_len = ExpLen, data = Data}) ->
    #rdpdr_io{device_id = DevId, file_id = FileId, req_id = ReqId} = IO,
    <<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_DEVICE_IOREQUEST:16/little,
      DevId:32/little, FileId:32/little, ReqId:32/little,
      ?IRP_MJ_DEVICE_CONTROL:32/little, 0:32,
      ExpLen:32/little, (byte_size(Data)):32/little,
      Code:32/little, 0:20/unit:8, Data/binary>>;

encode(_) -> error(bad_record).

-bitset({io_reqs, [{skip, 16}, set_security, query_security, lock_control,
    dir_control, set_info, query_info, set_volume_info, query_volume_info,
    device_control, shutdown, flush_buffers, write, read, close, cleanup,
    create]}).
-bitset({extpdu, [{skip, 29}, user_loggedon, client_name, device_remove]}).
-bitset({cap_flags, [{skip, 31}, async_io]}).


encode_cap(Type, Version, Data) ->
    <<Type:16/little, (byte_size(Data)+8):16/little,
      Version:32/little, Data/binary>>.

encode_cap(#rdpdr_cap_general{os_type = OSType, os_version = OSVer,
                              version = {VerMaj, VerMin},
                              ioreqs = IOReqList,
                              pdus = PduList,
                              flags = FlagList,
                              specials = Specials}) ->
    IOCode1 = encode_io_reqs(IOReqList),
    ExtPDUs = encode_extpdu(PduList),
    Flags1 = encode_cap_flags(FlagList),
    DV1 = <<OSType:32/little, OSVer:32/little,
            VerMaj:16/little, VerMin:16/little,
            IOCode1:32/little, 0:32/little,
            ExtPDUs:32/little, Flags1:32/little,
            0:32/little>>,
    case Specials of
        none -> encode_cap(?CAP_GENERAL_TYPE, 1, DV1);
        _ ->
            DV2 = <<DV1/binary, Specials:32/little>>,
            encode_cap(?CAP_GENERAL_TYPE, 2, DV2)
    end;

encode_cap(#rdpdr_cap_printer{}) ->
    encode_cap(?CAP_PRINTER_TYPE, 1, <<>>);

encode_cap(#rdpdr_cap_port{}) ->
    encode_cap(?CAP_PORT_TYPE, 1, <<>>);

encode_cap(#rdpdr_cap_drive{}) ->
    encode_cap(?CAP_DRIVE_TYPE, 2, <<>>);

encode_cap(#rdpdr_cap_smartcard{}) ->
    encode_cap(?CAP_SMARTCARD_TYPE, 1, <<>>);

encode_cap(_) ->
    error(bad_cap_record).

-spec decode(binary()) -> {ok, pdu()} | {error, term()}.

decode(<<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_SERVER_ANNOUNCE:16/little,
        VerMaj:16/little, VerMin:16/little, ClientId:32/little>>) ->
    {ok, #rdpdr_srv_announce{version = {VerMaj, VerMin},
                             clientid = ClientId}};

decode(<<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_CLIENTID_CONFIRM:16/little,
        VerMaj:16/little, VerMin:16/little, ClientId:32/little>>) ->
    {ok, #rdpdr_clientid_confirm{version = {VerMaj, VerMin},
                                 clientid = ClientId}};

decode(<<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_CLIENT_NAME:16/little,
        UnicodeFlag:32/little, _CodePage:32/little, NameLen:32/little,
        NameBin:NameLen/binary>>) ->
    Name = case UnicodeFlag of
        1 -> unicode:characters_to_list(NameBin, {utf16, little});
        0 -> unicode:characters_to_list(NameBin, utf8)
    end,
    {ok, #rdpdr_client_name_req{unicode = (UnicodeFlag =:= 1),
                                name = lists:takewhile(fun (A) -> A =/= 0 end, Name)}};

decode(<<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_SERVER_CAP:16/little,
         NumCaps:16/little, _Pad:16, CapsBin/binary>>) ->
    case decode_caps(CapsBin) of
        {ok, Caps0} when length(Caps0) >= NumCaps ->
            Caps1 = lists:sublist(Caps0, NumCaps),
            {ok, #rdpdr_server_caps{caps = Caps1}};
        {ok, Caps} ->
            {error, {bad_caps_length, length(Caps), NumCaps}};
        {error, _} = Err ->
            Err
    end;
decode(<<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_CLIENT_CAP:16/little,
         NumCaps:16/little, _Pad:16, CapsBin/binary>>) ->
    case decode_caps(CapsBin) of
        {ok, Caps0} when length(Caps0) >= NumCaps ->
            Caps1 = lists:sublist(Caps0, NumCaps),
            {ok, #rdpdr_client_caps{caps = Caps1}};
        {ok, Caps} ->
            {error, {bad_caps_length, length(Caps), NumCaps}};
        {error, _} = Err ->
            Err
    end;

decode(<<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_DEVICELIST_ANNOUNCE:16/little,
         NumDevs:32/little, DevsBin/binary>>) ->
    case decode_devs(DevsBin) of
        {ok, Devs} when length(Devs) == NumDevs ->
            {ok, #rdpdr_device_announce{devices = Devs}};
        {ok, Devs} ->
            {error, {bad_devs_length, length(Devs), NumDevs}};
        {error, _} = Err ->
            Err
    end;

decode(<<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_DEVICELIST_REMOVE:16/little,
         NumDevs:32/little, DevIdsBin/binary>>) ->
    DevIds = [ Id || <<Id:32/little>> <= DevIdsBin ],
    if
        length(DevIds) == NumDevs ->
            {ok, #rdpdr_device_remove{device_ids = DevIds}};
        true ->
            {error, {bad_devs_length, length(DevIds), NumDevs}}
    end;

decode(<<?RDPDR_CTYP_CORE:16/little, ?PAKID_CORE_DEVICE_IOCOMPLETION:16/little,
         DevId:32/little, ReqId:32/little, Status:32/little, Rest/binary>>) ->
    IO = #rdpdr_io{device_id = DevId,
                   req_id = ReqId},
    {ok, #rdpdr_io_resp{io = IO,
                        status = msrpce:decode_ntstatus(Status),
                        data = Rest}};

decode(_) ->
    {error, bad_packet}.

decode(#rdpdr_io_resp{io = IO, data = Data}, #rdpdr_open_req{}) ->
    case Data of
        <<FileId:32/little>> ->
            Status = ok;
        <<FileId:32/little, StatusByte>> ->
            Status = case StatusByte of
                0 -> superseded;
                1 -> opened;
                3 -> overwritten
            end
    end,
    {ok, #rdpdr_open_resp{io = IO, file_id = FileId, status = Status}};

decode(#rdpdr_io_resp{io = IO, data = Data}, #rdpdr_control_req{}) ->
    <<DataLen:32/little, OutData:DataLen/binary>> = Data,
    {ok, #rdpdr_control_resp{io = IO, data = OutData}};

decode(#rdpdr_io_resp{io = IO, data = _Data}, #rdpdr_close_req{}) ->
    {ok, #rdpdr_close_resp{io = IO}};

decode(_, _) -> {error, bad_io_response}.

-define(RDPDR_DTYP_SERIAL, 16#0001).
-define(RDPDR_DTYP_PARALLEL, 16#0002).
-define(RDPDR_DTYP_PRINT, 16#0004).
-define(RDPDR_DTYP_FS, 16#0008).
-define(RDPDR_DTYP_SMARTCARD, 16#0020).

decode_devs(<<Type:32/little, Id:32/little, DosNameNul:8/binary,
              DataLen:32/little, Data:DataLen/binary, Rest/binary>>) ->
    [DosNameBin | _] = binary:split(DosNameNul, <<0>>),
    DosName = unicode:characters_to_list(DosNameBin, utf8),
    case decode_one_dev(Type, Id, DosName, Data) of
        {ok, Dev} ->
            case decode_devs(Rest) of
                {ok, RestDevs} -> {ok, [Dev | RestDevs]};
                {error, _} = Err -> Err
            end;
        {error, _} = Err -> Err
    end;
decode_devs(<<>>) -> {ok, []};
decode_devs(_) -> {error, invalid_device}.

decode_one_dev(?RDPDR_DTYP_SERIAL, Id, DosName, _) ->
    {ok, #rdpdr_dev_serial{id = Id, dos_name = DosName}};

decode_one_dev(?RDPDR_DTYP_PARALLEL, Id, DosName, _) ->
    {ok, #rdpdr_dev_parallel{id = Id, dos_name = DosName}};

decode_one_dev(?RDPDR_DTYP_PRINT, Id, DosName, _) ->
    {ok, #rdpdr_dev_printer{id = Id, dos_name = DosName}};

decode_one_dev(?RDPDR_DTYP_FS, Id, DosName, FullNameBin) ->
    FullNameNul = unicode:characters_to_list(FullNameBin, {utf16, little}),
    FullName = lists:takewhile(fun (A) -> A =/= 0 end, FullNameNul),
    {ok, #rdpdr_dev_fs{id = Id, dos_name = DosName, name = FullName}};

decode_one_dev(?RDPDR_DTYP_SMARTCARD, Id, DosName, _) ->
    {ok, #rdpdr_dev_smartcard{id = Id, dos_name = DosName}};

decode_one_dev(Typ, Id, DosName, _) ->
    {error, {unknown_dev_type, Typ, Id, DosName}}.

-type dev_type() :: serial | parallel | printer | fs | smartcard.
-type dev() :: #rdpdr_dev_serial{} | #rdpdr_dev_parallel{} |
    #rdpdr_dev_printer{} | #rdpdr_dev_fs{} | #rdpdr_dev_smartcard{}.

-spec decode_caps(binary()) -> {ok, [cap()]} | {error, term()}.
decode_caps(<<CapType:16/little, Len:16/little, Version:32/little,
             Data:(Len-8)/binary, Rest/binary>>) ->
    case decode_one_cap(CapType, Version, Data) of
        {ok, Cap} ->
            case decode_caps(Rest) of
                {ok, RestCaps} -> {ok, RestCaps ++ [Cap]};
                {error, _} = Err -> Err
            end;
        {error, _} = Err -> Err
    end;
decode_caps(<<>>) -> {ok, []}.

-spec decode_one_cap(integer(), integer(), binary()) -> {ok, cap()} | {error, term()}.
decode_one_cap(?CAP_GENERAL_TYPE, Ver, <<OSType:32/little, OSVer:32/little,
                                         VerMaj:16/little, VerMin:16/little,
                                         IoCode1:32/little, _IoCode2:32/little,
                                         ExtPDUs:32/little, Flags1:32/little,
                                         _Flags2:32/little, Rest/binary>>) ->
    case Ver of
        1 -> <<>> = Rest, Specials = none;
        2 -> <<Specials:32/little>> = Rest
    end,
    IOReqs = decode_io_reqs(IoCode1),
    ExtPdus = decode_extpdu(ExtPDUs),
    Flags = decode_cap_flags(Flags1),
    {ok, #rdpdr_cap_general{os_type = OSType, os_version = OSVer,
                            version = {VerMaj, VerMin},
                            ioreqs = IOReqs,
                            pdus = ExtPdus,
                            flags = Flags,
                            specials = Specials}};

decode_one_cap(?CAP_PRINTER_TYPE, 1, _) ->
    {ok, #rdpdr_cap_printer{}};

decode_one_cap(?CAP_PORT_TYPE, 1, _) ->
    {ok, #rdpdr_cap_port{}};

decode_one_cap(?CAP_DRIVE_TYPE, 2, _) ->
    {ok, #rdpdr_cap_drive{}};

decode_one_cap(?CAP_SMARTCARD_TYPE, 1, _) ->
    {ok, #rdpdr_cap_smartcard{}};

decode_one_cap(Other, _Ver, _Data) ->
    {error, {unknown_rdpdr_cap, Other}}.
