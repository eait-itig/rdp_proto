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

-module(rdpp).

-compile([{parse_transform, lager_transform}]).
-compile([{parse_transform, bitset_parse_transform}]).

-include("kbd.hrl").
-include("x224.hrl").
-include("rdpp.hrl").

-export([decode_client/1, decode_server/1, decode_connseq/1]).
-export([encode_protocol_flags/1, decode_protocol_flags/1]).
-export([decode_basic/1, decode_sharecontrol/1]).
-export([encode_basic/1, encode_sharecontrol/1]).
-export([encode_ts_order/1, encode_ts_update_bitmaps/1]).
-export([decode_ts_confirm/2]).
-export([encode_vchan/1, decode_vchan/2]).
-export([pretty_print/1]).
-export([encode_compr_flags/1, decode_compr_flags/1]).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(ts_security);
?pp(ts_info);
?pp(ts_demand);
?pp(ts_confirm);
?pp(ts_redir);
?pp(ts_deactivate);
?pp(ts_sharedata);
?pp(ts_license_vc);
?pp(ts_sync);
?pp(ts_control);
?pp(ts_fontlist);
?pp(ts_fontmap);
?pp(ts_input);
?pp(ts_heartbeat);

?pp(ts_update_orders);
?pp(ts_order_opaquerect);
?pp(ts_order_srcblt);
?pp(ts_order_line);

?pp(ts_bitmap);
?pp(ts_bitmap_comp_info);
?pp(ts_update_bitmaps);

?pp(ts_inpevt_sync);
?pp(ts_inpevt_key);
?pp(ts_inpevt_unicode);
?pp(ts_inpevt_mouse);
?pp(ts_inpevt_wheel);

?pp(ts_cap_general);
?pp(ts_cap_bitmap);
?pp(ts_cap_share);
?pp(ts_cap_order);
?pp(ts_cap_input);
?pp(ts_cap_font);
?pp(ts_cap_pointer);
?pp(ts_cap_vchannel);
?pp(ts_cap_control);
?pp(ts_cap_activation);
?pp(ts_cap_multifrag);
?pp(ts_cap_gdip);
?pp(ts_cap_bitmapcache);
?pp(ts_cap_bitmapcache_cell);
?pp(ts_cap_brush);
?pp(ts_cap_large_pointer);
?pp(ts_cap_bitmap_codecs);
?pp(ts_cap_bitmap_codec);
?pp(ts_cap_colortable);
?pp(ts_cap_surface);

?pp(ts_vchan);

?pp(ts_session_info_logon);
?pp(ts_session_info_error);

?pp(ts_autodetect_req);
?pp(ts_autodetect_resp);
?pp(rdp_rtt);
pretty_print(_, _) ->
    no.

-bitset({sec_flags_bits, [flagshi_valid, heartbeat, autodetect_rsp,
    autodetect_req, salted_mac, redirection, encrypt_license, skip, license,
    info, ignore_seqno, reset_seqno, encrypt, multitrans_rsp, multitrans_req,
    security]}).
-bitset({protocol_flags, [{skip,28}, credssp_early, rdstls, credssp, ssl]}).
-bitset({vchan_flags, [{skip,8}, mppc_flushed, mppc_at_front, compression,
    skip, {compress_type, 4}, {skip,9}, resume, suspend, show_protocol,
    {skip, 2}, last, first]}).
-bitset({ts_cap_general_flags, [{skip, 5}, short_bitmap_hdr, {skip, 5},
    salted_mac, autoreconnect, long_creds, skip, fastpath, refresh_rect,
    suppress_output]}).
-bitset({ts_cap_order_flags, [{skip,8}, extra, solid_pattern_brush_only,
    colorindex, skip, zeroboundsdeltas, skip, negotiate, skip]}).
-bitset({ts_cap_orders, [
    {dstblt,8}, {patblt,8}, {scrblt,8}, {memblt,8}, {mem3blt,8}, {skip,16}, {drawninegrid,8},
    {lineto,8}, {multidrawninegrid,8}, {skip,8}, {savebitmap,8}, {skip,24}, {multidstblt,8},
    {multipatblt,8}, {multiscrblt,8}, {multiopaquerect,8}, {fastindex,8}, {polygonsc,8},
    {polygoncb,8}, {polyline,8}, {skip,8}, {fastglyph,8}, {ellipsesc,8}, {ellipsecb,8},
    {index,8}, {skip,32}
    ]}).
-bitset({ts_cap_input_flags, [{skip, 10}, fastpath2, unicode, fastpath,
    mousex, skip, scancodes]}).
-bitset({ts_cap_bitmap_flags, [{skip,4}, skip_alpha, subsampling, dynamic_bpp,
    skip, resize, compression, multirect]}).
-bitset({ts_cap_surface_flags, [{skip,25}, streamsurfacebits, skip,
    framemarker, {skip,2}, setsurfacebits, skip]}).
-bitset({ts_inpevt_sync_flags, [{skip,12}, kanalock, capslock, numlock,
    scrolllock]}).
-bitset({ts_info_perf_flags, [{skip,23}, composition, font_smoothing,
    no_cursor_settings, no_cursor_shadow, skip, no_themes, no_menu_anim,
    no_full_win_drag, no_wallpaper]}).
-bitset({ts_info_flags, [
    {skip,6}, rail_hd, {skip,2}, no_video, audio_in, saved_creds, no_audio, smartcard_pin,
    mouse_wheel, logon_errors, rail, force_encrypt, remote_console_audio, {skip,4},
    windows_key, compression, logon_notify, maximize_shell, unicode, autologon, skip,
    disable_salute, mouse
    ]}).
-bitset({compr_flags, [flushed, at_front, compressed, skip, {type,4}]}).

decode_client(Bin) ->
    decode(Bin, decode_output).

decode_server(Bin) ->
    decode(Bin, decode_input).

decode(Bin, Dirn) ->
    maybe([
        fun decoder_fastpath/2,
        fun decoder_tpkt/1,
        fun decoder_x224/2,
        fun decoder_mcs_generic/3
    ], [Bin, Dirn]).

decode_connseq(Bin) ->
    maybe([
        fun decoder_tpkt/1,
        fun decoder_x224/2,
        fun decoder_mcs_ci/3,
        fun decoder_mcs_cr/3,
        fun decoder_mcs_generic/3
    ], [Bin]).

decoder_fastpath(Bin, Dirn) ->
    case fastpath:Dirn(Bin) of
        {ok, Pdu, Rem} ->
            {return, {ok, {fp_pdu, Pdu}, Rem}};
        {error, _} ->
            {continue, [Bin]}
    end.

decoder_tpkt(Bin) ->
    case tpkt:decode(Bin) of
        {ok, Body, Rem} ->
            {continue, [Body, Rem]};
        {error, Reason} ->
            {return, {error, {tpkt, Reason}}}
    end.

decoder_x224(Body, Rem) ->
    case x224:decode(Body) of
        {ok, #x224_dt{eot = 1, tpdunr = 0, data = McsData} = Pdu} ->
            {continue, [Pdu, McsData, Rem]};
        {ok, Pdu} ->
            {return, {ok, {x224_pdu, Pdu}, Rem}};
        {error, Reason} ->
            {return, {error, {x224, Reason}}}
    end.

decoder_mcs_generic(Pdu, McsData, Rem) ->
    case mcsgcc:decode(McsData) of
        {ok, McsPkt} ->
            {return, {ok, {mcs_pdu, McsPkt}, Rem}};
        _Err ->
            {return, {ok, {x224_pdu, Pdu}, Rem}}
    end.

decoder_mcs_ci(Pdu, McsData, Rem) ->
    case mcsgcc:decode_ci(McsData) of
        {ok, McsPkt} ->
            {return, {ok, {mcs_pdu, McsPkt}, Rem}};
        _Other ->
            {continue, [Pdu, McsData, Rem]}
    end.

decoder_mcs_cr(Pdu, McsData, Rem) ->
    case mcsgcc:decode_cr(McsData) of
        {ok, McsPkt} ->
            {return, {ok, {mcs_pdu, McsPkt}, Rem}};
        _Err ->
            {continue, [Pdu, McsData, Rem]}
    end.

-spec decode_sec_flags(integer()) -> {Type :: atom(), Flags :: [atom()]}.
decode_sec_flags(Flags) ->
    FlagSet = sets:from_list(decode_sec_flags_bits(Flags)),
    TypesSet = sets:from_list([autodetect_rsp, autodetect_req, redirection,
        license, info, multitrans_rsp, multitrans_req, security, heartbeat]),
    TypeSet = sets:intersection(FlagSet, TypesSet),
    Type = case sets:to_list(TypeSet) of
        [T] -> T;
        [] -> unknown
    end,
    {Type, sets:to_list(sets:subtract(FlagSet, TypesSet))}.

-spec encode_sec_flags({Type :: atom(), Flags :: [atom()]}) -> integer().
encode_sec_flags({Type, Flags}) ->
    encode_sec_flags_bits([Type | Flags]).

frags(<<Frag:1200/binary, Rest/binary>>) -> [Frag | frags(Rest)];
frags(Rest) -> [Rest].

wrap_frags(first, BaseFlags, [Frag]) ->
    Pdu = #ts_vchan{flags = BaseFlags ++ [first, last], data = Frag},
    [Pdu];
wrap_frags(first, BaseFlags, [Frag | Rest]) ->
    Pdu = #ts_vchan{flags = BaseFlags ++ [first], data = Frag},
    [Pdu | wrap_frags(last, BaseFlags, Rest)];
wrap_frags(last, BaseFlags, [Frag]) ->
    Pdu = #ts_vchan{flags = BaseFlags ++ [last], data = Frag},
    [Pdu];
wrap_frags(last, BaseFlags, [Frag | Rest]) ->
    Pdu = #ts_vchan{flags = BaseFlags, data = Frag},
    [Pdu | wrap_frags(last, BaseFlags, Rest)].

-spec encode_vchan(#ts_vchan{}) -> [binary()].
encode_vchan(#ts_vchan{flags = FlagList, data = Data}) ->
    BaseFlags = FlagList -- [first, last],
    Pdus = wrap_frags(first, BaseFlags, frags(Data)),
    Len = byte_size(Data),
    lists:map(fun (#ts_vchan{flags = FinalFlagList, data = FragData}) ->
        Flags = encode_vchan_flags(FinalFlagList),
        <<Len:32/little, Flags:32/little, FragData/binary>>
    end, Pdus).

-spec decode_vchan(binary(), [binary()]) -> {ok, #ts_vchan{}} |
    {fragment, [binary()]} | {error, term()}.
decode_vchan(<<Len:32/little, Flags:32/little, Rest/binary>>, Frags0) ->
    FlagList = decode_vchan_flags(Flags),
    case {lists:member(first, FlagList), lists:member(last, FlagList)} of
        {true, true} ->
            <<Data:Len/binary, Pad/binary>> = Rest,
            PadLen = 8*byte_size(Pad),
            <<0:PadLen>> = Pad,
            {ok, #ts_vchan{flags = FlagList, data = Data}};
        {false, true} ->
            <<Data:Len/binary, Pad/binary>> = iolist_to_binary(
                lists:reverse([Rest | Frags0])),
            PadLen = 8*byte_size(Pad),
            <<0:PadLen>> = Pad,
            {ok, #ts_vchan{flags = [first | FlagList], data = Data}};
        {true, false} ->
            {fragment, [Rest]};
        {false, false} ->
            {fragment, [Rest | Frags0]}
    end;
decode_vchan(_, _) ->
    {error, bad_packet}.

encode_sharecontrol(Pdu) ->
    {InnerType, Inner} = case Pdu of
        #ts_demand{} -> {16#1, encode_ts_demand(Pdu)};
        #ts_confirm{} -> {16#3, encode_ts_confirm(Pdu)};
        #ts_deactivate{} -> {16#6, encode_ts_deactivate(Pdu)};
        #ts_redir{} -> {16#a, encode_ts_redir(Pdu)};
        #ts_sharedata{} -> {16#7, encode_sharedata(Pdu)}
    end,
    Channel = element(2, Pdu),
    Length = byte_size(Inner) + 6,
    true = (Length < 1 bsl 16),
    Version = 16#01,
    <<Type:16/big>> = <<Version:12/big, InnerType:4>>,
    {ok, <<Length:16/little, Type:16/little, Channel:16/little, Inner/binary>>}.

decode_sharecontrol(Bin) -> decode_sharecontrol(Bin, true).
decode_sharecontrol(Bin, StripN) ->
    case Bin of
        <<N:32/little, Length:16/little, Rest/binary>> when StripN and ((N =:= 0) or (N =:= 48)) ->
            if
                (byte_size(Rest) == Length - 2) ->
                    _ = lager:debug("sharecontrol stripping initial 4 bytes"),
                    decode_sharecontrol(<<Length:16/little, Rest/binary>>, false);
                true ->
                    {error, bad_length}
            end;
        <<Length:16/little, Type:16/little, Chan:16/little, Rest/binary>> ->
            case <<Type:16/big>> of
                <<1:12/big, InnerType:4>> ->
                    RealLength = byte_size(Rest) + 6,
                    if RealLength == Length ->
                        case InnerType of
                            16#1 -> decode_ts_demand(Chan, Rest);
                            16#3 -> decode_ts_confirm(Chan, Rest);
                            16#6 -> decode_ts_deactivate(Chan, Rest);
                            16#7 -> decode_sharedata(Chan, Rest);
                            16#a -> decode_ts_redir(Chan, Rest);
                            Type ->
                                _ = lager:warning("unhandled sharecontrol: ~p", [Type]),
                                {error, badpacket}
                        end;
                    true ->
                        {error, badlength}
                    end;
                _ ->
                    {error, {bad_type, Type}}
            end;
        _ ->
            {error, badpacket}
    end.

zero_pad(Bin, Len) when is_list(Bin) ->
    zero_pad(list_to_binary(Bin), Len);
zero_pad(Bin, Len) ->
    Rem = Len - byte_size(Bin),
    <<Bin/binary, 0:Rem/unit:8>>.

decode_tscaps(0, _) -> [];
decode_tscaps(N, Bin) ->
    <<Type:16/little, Size:16/little, Rest/binary>> = Bin,
    Len = Size - 4,
    <<Data:Len/binary, Rem/binary>> = Rest,
    [decode_tscap(Type, Data) | decode_tscaps(N-1, Rem)].

decode_tscap(16#1, Bin) ->
    <<MajorNum:16/little, MinorNum:16/little, _:16, _:16, _:16, ExtraFlags:16/little, _:16, _:16, _:16, RefreshRect:8, SuppressOutput:8>> = Bin,

    Major = case MajorNum of 1 -> windows; 2 -> os2; 3 -> macintosh; 4 -> unix; 5 -> ios; 6 -> osx; 7 -> android; _ -> unknown end,
    Minor = case MinorNum of 1 -> win31x; 2 -> win95; 3 -> winnt; 4 -> os2v21; 5 -> powerpc; 6 -> macintosh; 7 -> native_x11; 8 -> pseudo_x11; _ -> unknown end,

    Flags = decode_ts_cap_general_flags_bin(
        <<ExtraFlags:16/big, RefreshRect:1, SuppressOutput:1>>),

    #ts_cap_general{os = [Major, Minor], flags = Flags};

decode_tscap(16#2, Bin) ->
    <<Bpp:16/little, _:16, _:16, _:16, Width:16/little, Height:16/little, _:16, Resize:16/little, Compression:16/little, _:8, DrawingFlags:8, Multirect:16/little, _:16>> = Bin,
    FlagSet = decode_ts_cap_bitmap_flags_bin(
        <<DrawingFlags:8, Resize:1, Compression:1, Multirect:1>>),
    #ts_cap_bitmap{bpp = Bpp, flags = FlagSet, width = Width, height = Height};

decode_tscap(16#3, Bin) ->
    <<_TermDesc:16/unit:8, _:32, _:16, _:16, _:16, _:16, _:16, BaseFlags:16/little, OrderSupport:32/binary, _/binary>> = Bin,
    FlagSet = decode_ts_cap_order_flags(BaseFlags),
    OrderSet = decode_ts_cap_orders_bin(OrderSupport),
    #ts_cap_order{flags = FlagSet, orders = OrderSet};

decode_tscap(16#5, Bin) ->
    <<_Flags:16/little, RemoteDetach:16/little, Control:16/little, Detach:16/little>> = Bin,
    FlagAtoms = if (RemoteDetach =/= 0) -> [{remote_detach, RemoteDetach}]; true -> [] end,
    ControlAtom = case Control of
        2 -> never;
        _ -> Control
    end,
    DetachAtom = case Detach of
        2 -> never;
        _ -> Detach
    end,
    #ts_cap_control{flags = FlagAtoms, control = ControlAtom, detach = DetachAtom};

decode_tscap(16#7, Bin) ->
    <<HelpKey:16/little, _:16, HelpExKey:16/little, WmKey:16/little>> = Bin,
    #ts_cap_activation{helpkey = HelpKey, helpexkey = HelpExKey, wmkey = WmKey};

decode_tscap(16#8, Bin) ->
    <<Color:16/little, _:16, CacheSize:16/little>> = Bin,
    Flags = if Color == 1 -> [color]; true -> [] end,
    #ts_cap_pointer{flags = Flags, cache_size = CacheSize};

decode_tscap(16#9, Bin) ->
    <<Chan:16/little, _:16>> = Bin,
    #ts_cap_share{channel = Chan};

decode_tscap(16#d, Bin) ->
    <<InputFlags:16/little, _:16, Layout:32/little, Type:32/little, SubType:32/little, FunKeys:32/little, ImeBin:64/binary>> = Bin,
    FlagSet = decode_ts_cap_input_flags(InputFlags),
    #ts_cap_input{flags = FlagSet, ime = ImeBin, kbd_layout = Layout, kbd_type = Type, kbd_sub_type = SubType, kbd_fun_keys = FunKeys};

decode_tscap(16#e, Bin) ->
    case Bin of
        <<>> -> #ts_cap_font{};
        <<Fontlist:16/little, _:16>> ->
            Flags = if Fontlist == 1 -> [fontlist]; true -> [] end,
            #ts_cap_font{flags = Flags}
    end;

decode_tscap(16#14, Bin) ->
    maybe([
        fun(V) ->
            case Bin of
                <<Flags:32/little>> ->
                    {continue, [V, Flags]};
                <<Flags:32/little, ChunkSize:32/little>> ->
                    V2 = V#ts_cap_vchannel{chunksize = ChunkSize},
                    {continue, [V2, Flags]}
            end
        end,
        fun(V, Flags) ->
            <<_:30, CompressCtoS:1, CompressStoC:1>> = <<Flags:32/big>>,
            FlagAtoms = if CompressCtoS == 1 -> [compress_cs]; true -> [] end ++
                        if CompressStoC == 1 -> [compress_sc]; true -> [] end,
            {return, V#ts_cap_vchannel{flags=FlagAtoms}}
        end
    ], [#ts_cap_vchannel{}]);

decode_tscap(16#16, Bin) ->
    <<Supported:32/little, GdipVersion:32/little, CacheSupported:32/little, CacheEntries:10/binary, CacheChunkSizes:8/binary, ImageCacheProps:6/binary>> = Bin,
    FlagAtoms = if Supported > 0 -> [supported]; true -> [] end ++
                if CacheSupported > 0 -> [cache]; true -> [] end,
    {<<>>, CacheEntryPlist} = lists:foldl(fun(Atom, {IBin, Acc}) ->
        <<Val:16/little, Rest/binary>> = IBin,
        {Rest, [{Atom, Val} | Acc]}
    end, {CacheEntries, []}, [graphics,brush,pen,image,image_attr]),
    {<<>>, CacheSizePlist} = lists:foldl(fun(Atom, {IBin, Acc}) ->
        <<Val:16/little, Rest/binary>> = IBin,
        {Rest, [{Atom, Val} | Acc]}
    end, {CacheChunkSizes, []}, [graphics,brush,pen,image_attr]),
    {<<>>, ImageCachePlist} = lists:foldl(fun(Atom, {IBin, Acc}) ->
        <<Val:16/little, Rest/binary>> = IBin,
        {Rest, [{Atom, Val} | Acc]}
    end, {ImageCacheProps, []}, [size, total, max]),
    #ts_cap_gdip{flags=FlagAtoms, version = GdipVersion, cache_entries=CacheEntryPlist, cache_sizes=CacheSizePlist, image_cache=ImageCachePlist};

decode_tscap(16#1a, Bin) ->
    <<MaxSize:32/little>> = Bin,
    #ts_cap_multifrag{maxsize = MaxSize};

decode_tscap(16#04, Bin) ->
    <<_Pad1:32, _Pad2:32, _Pad3:32, _Pad4:32, _Pad5:32, _Pad6:32, Caches/binary>> = Bin,
    <<Cache0Entries:16/little, Cache0CellSize:16/little,
      Cache1Entries:16/little, Cache1CellSize:16/little,
      Cache2Entries:16/little, Cache2CellSize:16/little>> = Caches,
    #ts_cap_bitmapcache{flags=[], cells=[
        #ts_cap_bitmapcache_cell{count = Cache0Entries, size = Cache0CellSize},
        #ts_cap_bitmapcache_cell{count = Cache1Entries, size = Cache1CellSize},
        #ts_cap_bitmapcache_cell{count = Cache2Entries, size = Cache2CellSize}
    ]};

decode_tscap(16#13, Bin) ->
    <<Flags:16/little, _Pad2, NumCellCaches, Rest/binary>> = Bin,
    <<_:14, WaitingList:1, PersistentKeys:1>> = <<Flags:16/big>>,
    FlagAtoms = [rev2] ++
                if WaitingList == 1 -> [waiting_list]; true -> [] end ++
                if PersistentKeys == 1 -> [persistent_keys]; true -> [] end,
    {_Rem, Cells} = lists:foldl(fun(_, {CellBin, Acc}) ->
        <<CellInfo:32/little, CellRest/binary>> = CellBin,
        <<Persistent:1, NumEntries:31/big>> = <<CellInfo:32/big>>,
        CellFlags = if Persistent == 1 -> [persistent]; true -> [] end,
        Cell = #ts_cap_bitmapcache_cell{count = NumEntries, flags = CellFlags},
        {CellRest, [Cell | Acc]}
    end, {Rest, []}, lists:seq(1, NumCellCaches)),
    #ts_cap_bitmapcache{flags = FlagAtoms, cells = lists:reverse(Cells)};

decode_tscap(16#0f, Bin) ->
    <<SupportLevel:32/little>> = Bin,
    Flags = case SupportLevel of
        0 -> [];
        1 -> [color_8x8];
        2 -> [color_8x8, color_full];
        N when N > 2 -> [color_8x8, color_full, other]
    end,
    #ts_cap_brush{flags = Flags};

decode_tscap(16#1b, Bin) ->
    <<Flags:16/little>> = Bin,
    <<_:15, Support96:1>> = <<Flags:16/big>>,
    FlagAtoms = if Support96 == 1 -> [support_96x96]; true -> [] end,
    #ts_cap_large_pointer{flags = FlagAtoms};

decode_tscap(16#1c, Bin) ->
    <<Flags:32/little, _:32>> = Bin,
    FlagSet = decode_ts_cap_surface_flags(Flags),
    #ts_cap_surface{flags = FlagSet};

decode_tscap(16#1d, Bin) ->
    <<CodecCount, CodecsBin/binary>> = Bin,
    {<<>>, Codecs} = lists:foldl(fun(_, {CodecBin, Acc}) ->
        <<Guid:16/binary, Id, PropLen:16/little, PropBin:PropLen/binary, Rest/binary>> = CodecBin,
        {Name, Props} = case Guid of
            ?GUID_NSCODEC ->
                <<DynFidelity, Subsampling, ColorLossLevel>> = PropBin,
                {nscodec, [{dynamic_fidelity, DynFidelity == 1},
                           {subsampling, Subsampling == 1},
                           {color_loss_level, ColorLossLevel}]};
            ?GUID_JPEG ->
                <<Quality>> = PropBin,
                {jpeg, [{quality, Quality}]};
            ?GUID_REMOTEFX ->
                {remotefx, []};
            ?GUID_REMOTEFX_IMAGE ->
                {remotefx_image, PropBin};
            ?GUID_IGNORE ->
                {ignore, []};
            _ ->
                {unknown, PropBin}
        end,
        Codec = #ts_cap_bitmap_codec{codec = Name, guid = Guid, id = Id, properties = Props},
        {Rest, [Codec | Acc]}
    end, {CodecsBin, []}, lists:seq(1, CodecCount)),
    #ts_cap_bitmap_codecs{codecs = lists:reverse(Codecs)};

decode_tscap(16#0a, Bin) ->
    <<Size:16/little, _:16>> = Bin,
    #ts_cap_colortable{cache_size = Size};

decode_tscap(Type, Bin) ->
    {Type, Bin}.

encode_tscap(#ts_cap_general{os = [Major,Minor], flags=Flags}) ->
    MajorNum = case Major of windows -> 1; os2 -> 2; macintosh -> 3; unix -> 4; ios -> 5; osx -> 6; android -> 7; _ -> 0 end,
    MinorNum = case Minor of win31x -> 1; win95 -> 2; winnt -> 3; os2v21 -> 4; powerpc -> 5; macintosh -> 6; native_x11 -> 7; pseudo_x11 -> 8; _ -> 0 end,
    <<ExtraFlags:16/big, RefreshRect:1, SuppressOutput:1>> = encode_ts_cap_general_flags_bin(Flags),
    Inner = <<MajorNum:16/little, MinorNum:16/little, 16#200:16/little, 0:16, 0:16, ExtraFlags:16/little, 0:16, 0:16, 0:16, RefreshRect:8, SuppressOutput:8>>,
    encode_tscap({16#01, Inner});

encode_tscap(#ts_cap_vchannel{flags=FlagAtoms, chunksize=ChunkSize}) ->
    CompressCS = case lists:member(compress_cs, FlagAtoms) of true -> 1; _ -> 0 end,
    CompressSC = case lists:member(compress_sc, FlagAtoms) of true -> 1; _ -> 0 end,
    <<Flags:32/big>> = <<0:30, CompressCS:1, CompressSC:1>>,
    Inner = <<Flags:32/little, ChunkSize:32/little>>,
    encode_tscap({16#14, Inner});

encode_tscap(#ts_cap_bitmap{bpp = Bpp, flags = Flags, width = Width, height = Height}) ->
    <<DrawingFlags:8, Resize:1, Compression:1, Multirect:1>> = encode_ts_cap_bitmap_flags_bin(Flags),
    Inner = <<Bpp:16/little, 1:16/little, 1:16/little, 1:16/little, Width:16/little, Height:16/little, 0:16, Resize:16/little, Compression:16/little, 1:8, DrawingFlags:8, Multirect:16/little, 0:16>>,
    % this is different in the example versus spec
    encode_tscap({16#02, Inner});

encode_tscap(#ts_cap_order{flags = Flags, orders = Orders}) ->
    OrderSupport = encode_ts_cap_orders_bin(Orders),
    BaseFlags = encode_ts_cap_order_flags(Flags),
    Inner = <<0:16/unit:8, 16#40420f00:32/big, 1:16/little, 20:16/little, 0:16, 1:16/little, 0:16, BaseFlags:16/little, OrderSupport/binary, 16#06a1:16/big, 0:16, 16#40420f00:32/big, 230400:32/little, 1:16/little, 0:16, 0:16, 0:16>>,
    encode_tscap({16#03, Inner});

encode_tscap(#ts_cap_share{channel = Chan}) ->
    Inner = <<Chan:16/little, 16#dce2:16/big>>,
    encode_tscap({16#09, Inner});

encode_tscap(#ts_cap_activation{helpkey=HelpKey, helpexkey=HelpExKey, wmkey=WmKey}) ->
    Inner = <<HelpKey:16/little, 0:16, HelpExKey:16/little, WmKey:16/little>>,
    encode_tscap({16#07, Inner});

encode_tscap(#ts_cap_control{control=ControlAtom, detach=DetachAtom}) ->
    Control = case ControlAtom of
        never -> 2
    end,
    Detach = case DetachAtom of
        never -> 2
    end,
    Inner = <<0:16, 0:16, Control:16/little, Detach:16/little>>,
    encode_tscap({16#05, Inner});

encode_tscap(#ts_cap_font{flags = Flags}) ->
    Fontlist = case lists:member(fontlist, Flags) of true -> 1; _ -> 0 end,
    Inner = <<Fontlist:16/little, 0:16>>,
    encode_tscap({16#0e, Inner});

encode_tscap(#ts_cap_pointer{flags = Flags, cache_size = CacheSize}) ->
    Color = case lists:member(color, Flags) of true -> 1; _ -> 0 end,
    Inner = <<Color:16/little, CacheSize:16/little, CacheSize:16/little>>,
    encode_tscap({16#08, Inner});

encode_tscap(#ts_cap_input{flags=Flags, kbd_layout=Layout, kbd_type=Type, kbd_sub_type=SubType, kbd_fun_keys=FunKeys, ime=Ime}) ->
    ImeBin = zero_pad(Ime, 64),
    InputFlags = encode_ts_cap_input_flags(Flags),
    Inner = <<InputFlags:16/little, 0:16, Layout:32/little, Type:32/little, SubType:32/little, FunKeys:32/little, ImeBin/binary>>,
    encode_tscap({16#0d, Inner});

encode_tscap(#ts_cap_multifrag{maxsize = MaxSize}) ->
    encode_tscap({16#1a, <<MaxSize:32/little>>});

encode_tscap(#ts_cap_gdip{flags=FlagAtoms, version=GdipVersion, cache_entries=CacheEntryPlist, cache_sizes=CacheSizePlist, image_cache=ImageCachePlist}) ->
    CacheEntries = lists:foldl(fun({Atom, Default}, Bin) ->
        Val = proplists:get_value(Atom, CacheEntryPlist, Default),
        <<Bin/binary, Val:16/little>>
    end, <<>>, [{graphics, 10},{brush, 5},{pen, 5},{image, 10},{image_attr, 2}]),
    CacheChunkSizes = lists:foldl(fun({Atom, Default}, Bin) ->
        Val = proplists:get_value(Atom, CacheSizePlist, Default),
        <<Bin/binary, Val:16/little>>
    end, <<>>, [{graphics, 512},{brush, 2048},{pen, 1024},{image_attr, 64}]),
    ImageCacheProps = lists:foldl(fun({Atom, Default}, Bin) ->
        Val = proplists:get_value(Atom, ImageCachePlist, Default),
        <<Bin/binary, Val:16/little>>
    end, <<>>, [{chunk, 4096}, {total, 256}, {max, 128}]),
    Supported = case lists:member(supported, FlagAtoms) of true -> 1; _ -> 0 end,
    CacheSupported = case lists:member(cache, FlagAtoms) of true -> 1; _ -> 0 end,
    Inner = <<Supported:32/little, GdipVersion:32/little, CacheSupported:32/little, CacheEntries/binary, CacheChunkSizes/binary, ImageCacheProps/binary>>,
    encode_tscap({16#16, Inner});

encode_tscap(#ts_cap_large_pointer{flags = FlagAtoms}) ->
    Support96 = case lists:member(support_96x96, FlagAtoms) of true -> 1; _ -> 0 end,
    <<Flags:16/big>> = <<0:15, Support96:1>>,
    encode_tscap({16#1b, <<Flags:16/little>>});

encode_tscap(#ts_cap_bitmap_codecs{codecs = Codecs}) ->
    CodecCount = length(Codecs),
    CodecsBin = lists:foldl(
        fun(Codec = #ts_cap_bitmap_codec{codec = Name, id = Id, properties = Props}, Acc) ->
            {Guid, PropBin} = case Name of
                nscodec ->
                    DynFidelity = case proplists:get_value(dynamic_fidelity, Props) of true -> 1; _ -> 0 end,
                    Subsampling = case proplists:get_value(subsampling, Props) of true -> 1; _ -> 0 end,
                    ColorLossLevel = case proplists:get_value(color_loss_level, Props) of I when is_integer(I) -> I; _ -> 0 end,
                    {?GUID_NSCODEC, <<DynFidelity, Subsampling, ColorLossLevel>>};
                jpeg ->
                    Quality = case proplists:get_value(quality, Props) of I when is_integer(I) -> I; _ -> 75 end,
                    {?GUID_JPEG, <<Quality>>};
                remotefx -> {?GUID_REMOTEFX, <<0:32>>};
                remotefx_image when is_binary(Props) -> {?GUID_REMOTEFX_IMAGE, Props};
                ignore -> {?GUID_IGNORE, <<0:32>>};
                _ when is_binary(Props) -> {Codec#ts_cap_bitmap_codec.guid, Props}
            end,
            PropLen = byte_size(PropBin),
            <<Acc/binary, Guid/binary, Id, PropLen:16/little, PropBin/binary>>
        end, <<>>, Codecs),
    encode_tscap({16#1d, <<CodecCount, CodecsBin/binary>>});

encode_tscap(#ts_cap_surface{flags = FlagList}) ->
    Flags = encode_ts_cap_surface_flags(FlagList),
    encode_tscap({16#1c, <<Flags:32/little, 0:32>>});

encode_tscap(#ts_cap_colortable{cache_size = Size}) ->
    encode_tscap({16#0a, <<Size:16/little, 0:16>>});

encode_tscap({Type, Bin}) ->
    Size = byte_size(Bin) + 4,
    <<Type:16/little, Size:16/little, Bin/binary>>.

decode_ts_demand(Chan, Bin) ->
    case Bin of
        <<ShareId:32/little, SDLen:16/little, Len:16/little, Rest/binary>> ->
            case Rest of
                <<SD:SDLen/binary, N:16/little, _:16, CapsBin/binary>> ->
                    RealLen = byte_size(CapsBin) + 4,
                    if (Len == RealLen) or (Len + 4 == RealLen) ->
                        Caps = decode_tscaps(N, CapsBin),
                        {ok, #ts_demand{channel = Chan, shareid = ShareId, sourcedesc = SD, capabilities = Caps}};
                    true ->
                        {error, {badlength, Len, RealLen}}
                    end;
                _ ->
                    {error, badpacket}
            end;
        _ ->
            {error, badpacket}
    end.

encode_ts_demand(#ts_demand{shareid = ShareId, sourcedesc = SourceDesc, capabilities = Caps}) ->
    N = length(Caps),
    CapsBin = lists:foldl(fun(Next, Bin) ->
        NextBin = encode_tscap(Next), <<Bin/binary, NextBin/binary>>
    end, <<>>, Caps),
    SDLen = byte_size(SourceDesc),
    Sz = byte_size(CapsBin) + 4,
    <<ShareId:32/little, SDLen:16/little, Sz:16/little, SourceDesc/binary, N:16/little, 0:16, CapsBin/binary, 0:32/little>>.

decode_ts_confirm(Chan, Bin) ->
    case Bin of
        <<ShareId:32/little, _:16, SDLen:16/little, Len:16/little, Rest/binary>> ->
            case Rest of
                <<SD:SDLen/binary, N:16/little, _:16, CapsBin/binary>> ->
                    RealLen = byte_size(CapsBin) + 4,
                    if (Len == RealLen) ->
                        Caps = decode_tscaps(N, CapsBin),
                        {ok, #ts_confirm{channel = Chan, shareid = ShareId, sourcedesc = SD, capabilities = Caps}};
                    true ->
                        {error, badlength}
                    end;
                _ ->
                    {error, badpacket}
            end;
        _ ->
            {error, badpacket}
    end.

encode_ts_confirm(#ts_confirm{}) ->
    <<>>.

decode_ts_deactivate(Chan, _Bin) ->
    {ok, #ts_deactivate{channel = Chan}}.

encode_ts_deactivate(#ts_deactivate{shareid = ShareId, sourcedesc = SourceDescIn}) ->
    SourceDesc = if is_binary(SourceDescIn) and (byte_size(SourceDescIn) > 0) -> SourceDescIn; true -> <<0>> end,
    Sz = byte_size(SourceDesc),
    <<ShareId:32/little, Sz:16/little, SourceDesc/binary>>.

decode_ts_redir(Chan, _Bin) ->
    {ok, #ts_redir{channel = Chan}}.

encode_ts_redir(#ts_redir{sessionid = Session, username = Username, domain = Domain, password = Password, cookie = Cookie, flags = Flags, address = NetAddress, fqdn = Fqdn}) ->
    InfoOnly = case lists:member(info_only, Flags) of true -> 1; _ -> 0 end,
    Smartcard = case lists:member(smartcard, Flags) of true -> 1; _ -> 0 end,
    Logon = case lists:member(logon, Flags) of true -> 1; _ -> 0 end,

    HasCookie = if is_binary(Cookie) and (byte_size(Cookie) > 0) -> 1; true -> 0 end,
    HasUsername = if is_binary(Username) and (byte_size(Username) > 0) -> 1; true -> 0 end,
    HasDomain = if is_binary(Domain) and (byte_size(Domain) > 0) -> 1; true -> 0 end,
    HasPassword = if is_binary(Password) and (byte_size(Password) > 0) -> 1; true -> 0 end,
    HasNetAddress = if is_binary(NetAddress) and (byte_size(NetAddress) > 0) -> 1; true -> 0 end,
    HasFqdn = if is_binary(Fqdn) and (byte_size(Fqdn) > 0) -> 1; true -> 0 end,

    %if (HasNetAddress == 1) andalso (HasCookie == 1) ->
    %   error(cookie_and_netaddr);
    %true -> ok end,

    UseCookieForTsv = 0,
    HasTsvUrl = 0,
    HasMultiNetAddr = 0,
    HasNetBios = 0,

    <<RedirFlags:32/big>> = <<0:19, UseCookieForTsv:1, HasTsvUrl:1, HasMultiNetAddr:1, HasNetBios:1, HasFqdn:1, InfoOnly:1, Smartcard:1, Logon:1, HasPassword:1, HasDomain:1, HasUsername:1, HasCookie:1, HasNetAddress:1>>,

    maybe([
        fun() ->
            {continue, [<<Session:32/little, RedirFlags:32/little>>]}
        end,
        fun(Base) ->
            {continue, [if HasNetAddress == 1 ->
                S = byte_size(NetAddress),
                <<Base/binary, S:32/little, NetAddress/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasCookie == 1 ->
                S = byte_size(Cookie),
                <<Base/binary, S:32/little, Cookie/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasUsername == 1 ->
                S = byte_size(Username),
                <<Base/binary, S:32/little, Username/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasDomain == 1 ->
                S = byte_size(Domain),
                <<Base/binary, S:32/little, Domain/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasPassword == 1 ->
                S = byte_size(Password),
                <<Base/binary, S:32/little, Password/binary>>;
            true -> Base end]}
        end,
        fun(Base) ->
            {continue, [if HasFqdn == 1 ->
                S = byte_size(Fqdn),
                <<Base/binary, S:32/little, Fqdn/binary>>;
            true -> Base end]}
        end,
        fun(Payload) ->
            Len = byte_size(Payload) + 4,
            {return, <<0:16, 16#0400:16/little, Len:16/little, Payload/binary, 0:9/unit:8>>}
        end
    ], []).

strip_compr_type([]) -> {{type, 0}, []};
strip_compr_type([type | Rest]) -> {{type,1}, Rest};
strip_compr_type([{type,N} | Rest]) -> {{type,N}, Rest};
strip_compr_type([Next | Rest0]) ->
    {Type, Rest1} = strip_compr_type(Rest0),
    {Type, [Next | Rest1]}.

decode_sharedata(Chan, Bin) ->
    case Bin of
        <<ShareId:32/little, _:8, Priority:8, Length:16/little, PduType:8, ComprFlags:8, CompressedLength:16/little, Rest/binary>> ->
            FlagAndTypeAtoms = decode_compr_flags(ComprFlags),
            {TypeTerm, FlagAtoms} = strip_compr_type(FlagAndTypeAtoms),
            {type, CompType} = TypeTerm,
            CompTypeAtom = case CompType of
                0 -> '8k';
                1 -> '64k';
                2 -> 'rdp6';
                3 -> 'rdp61';
                _ -> 'unknown'
            end,
            Compressed = lists:member(compressed, FlagAtoms),
            Prio = case Priority of 1 -> low; 2 -> medium; 4 -> high; _ -> unknown end,
            RealSize = byte_size(Rest),
            if Compressed and (CompressedLength == RealSize) ->
                {ok, #ts_sharedata{channel = Chan, shareid = ShareId, priority = Prio, flags = FlagAtoms, comptype = CompTypeAtom, data = {PduType, Rest}}};
            (not Compressed) -> %and (Length == RealSize) ->
                Inner = case PduType of
                    %16#02 -> decode_update(Rest);
                    31 -> decode_ts_sync(Rest);
                    20 -> decode_ts_control(Rest);
                    39 -> decode_ts_fontlist(Rest);
                    40 -> decode_ts_fontmap(Rest);
                    28 -> decode_ts_input(Rest);
                    33 -> decode_ts_refresh_rect(Rest);
                    35 -> decode_ts_suppress_output(Rest);
                    36 -> decode_ts_shutdown(Rest);
                    37 -> decode_ts_shutdown_denied(Rest);
                    38 -> decode_ts_session_info(Rest);
                    47 -> decode_ts_set_error_info(Rest);
                    _ -> {PduType, Rest}
                end,
                {ok, #ts_sharedata{channel = Chan, shareid = ShareId, priority = Prio, flags = FlagAtoms, data = Inner}};
            true ->
                {error, {badlength, Length, CompressedLength, RealSize}}
            end;
        _ ->
            {error, badpacket}
    end.

encode_sharedata(#ts_sharedata{shareid = ShareId, data = Pdu, priority = Prio, comptype = CompTypeAtom, flags = FlagAtoms}) ->
    {PduType, Inner} = case Pdu of
        %#ts_update{} -> {16#02, encode_ts_update(Pdu)};
        #ts_sync{} -> {31, encode_ts_sync(Pdu)};
        #ts_control{} -> {20, encode_ts_control(Pdu)};
        #ts_fontlist{} -> {39, encode_ts_fontlist(Pdu)};
        #ts_fontmap{} -> {40, encode_ts_fontmap(Pdu)};
        #ts_update_orders{} -> {2, encode_ts_update(Pdu)};
        #ts_update_bitmaps{} -> {2, encode_ts_update(Pdu)};
        #ts_monitor_layout{} -> {55, encode_ts_monitor_layout(Pdu)};
        {N, Data} -> {N, Data}
    end,
    CompType = case CompTypeAtom of '8k' -> 0; '64k' -> 1; 'rdp6' -> 2; 'rdp61' -> 3; I when is_integer(I) -> I; _ -> 0 end,
    Priority = case Prio of low -> 1; medium -> 2; high -> 4; _ -> 0 end,

    Flushed = case lists:member(flushed, FlagAtoms) of true -> 1; _ -> 0 end,
    AtFront = case lists:member(at_front, FlagAtoms) of true -> 1; _ -> 0 end,
    Compressed = case lists:member(compressed, FlagAtoms) of true -> 1; _ -> 0 end,
    <<Flags:4>> = <<Flushed:1, AtFront:1, Compressed:1, 0:1>>,

    Size = byte_size(Inner) + 4,
    true = (Size < 1 bsl 16),
    CompSize = 0,

    <<ShareId:32/little, 0:8, Priority:8, Size:16/little, PduType:8, Flags:4, CompType:4, CompSize:16/little, Inner/binary>>.

decode_ts_suppress_output(<<0, _:3/unit:8>>) ->
    #ts_suppress_output{allow_updates = false, rect = none};
decode_ts_suppress_output(<<1, _:3/unit:8,
            L:16/little, T:16/little, R:16/little, B:16/little>>) ->
    #ts_suppress_output{allow_updates = true, rect = {L, T, R, B}}.

decode_ts_refresh_rect(<<N, _:3/unit:8, Rects/binary>>) ->
    #ts_refresh_rect{rects = decode_rects(N, Rects)}.

decode_rects(0, _) -> [];
decode_rects(N, <<L:16/little, T:16/little, R:16/little, B:16/little, Rem/binary>>) ->
    [{L, T, R, B} | decode_rects(N - 1, Rem)].

decode_ts_sync(Bin) ->
    <<1:16/little, User:16/little>> = Bin,
    #ts_sync{user = User}.

encode_ts_sync(#ts_sync{user = User}) ->
    <<1:16/little, User:16/little>>.

decode_ntstatus(16#FFFFFFFA) -> no_permission;
decode_ntstatus(16#FFFFFFFB) -> session_bump;
decode_ntstatus(16#FFFFFFFC) -> reconnect_options;
decode_ntstatus(16#FFFFFFFD) -> terminate;
decode_ntstatus(16#FFFFFFFE) -> continue;
decode_ntstatus(16#FFFFFFFF) -> access_denied;
decode_ntstatus(0) -> success;
decode_ntstatus(Other) -> {other, Other}.

decode_session_id(16#00000000) -> bad_password;
decode_session_id(16#00000001) -> bad_password_update;
decode_session_id(16#00000002) -> fail;
decode_session_id(16#00000003) -> warning;
decode_session_id(Other) -> Other.

decode_ts_session_info(<<0:32/little, DomainLen:32/little, Domain:52/binary,
        UserNameLen:32/little, UserName:512/binary, SessionId:32/little>>) ->
    <<DomainCut:DomainLen/binary, _/binary>> = Domain,
    <<UserNameCut:UserNameLen/binary, _/binary>> = UserName,
    #ts_session_info_logon{user = UserNameCut, domain = DomainCut, sessionid = SessionId};
decode_ts_session_info(<<1:32/little, 1:16/little, _TotalSize:32/little,
        SessionId:32/little, DomainLen:32/little, UserNameLen:32/little,
        _Pad:558/binary, Domain:DomainLen/binary, UserName:UserNameLen/binary>>) ->
    #ts_session_info_logon{user = UserName, domain = Domain, sessionid = SessionId};
decode_ts_session_info(<<2:32/little, _/binary>>) ->
    #ts_session_info_logon{};
decode_ts_session_info(<<3:32/little, TotalSize:16/little, Rem/binary>>) ->
    Rem0Size = TotalSize - 2,
    <<Rem0:Rem0Size/binary, _Pad/binary>> = Rem,
    <<FieldMask:32/little, Rem1/binary>> = Rem0,
    <<_:30, Errors:1, AutoReconnect:1>> = <<FieldMask:32/big>>,
    Rem2 = case AutoReconnect of
        1 ->
            <<Len:32/little, _AutoReconInfo:Len/binary, Rest/binary>> = Rem1,
            Rest;
        0 ->
            Rem1
    end,
    case Errors of
        1 ->
            <<8:32/little, NotifTypeRaw:32/little, SessionIdRaw:32/little>> = Rem2,
            NotifType = decode_ntstatus(NotifTypeRaw),
            SessionId = decode_session_id(SessionIdRaw),
            #ts_session_info_error{status = {NotifType, SessionId}};
        0 ->
            <<>> = Rem2,
            #ts_session_info_logon{}
    end;
decode_ts_session_info(<<N:32/little, _/binary>>) ->
    error({unsupported_session_info, N}).

decode_ts_set_error_info(<<N:32/little>>) ->
    Info = case N of
        16#00000000 -> no_error;
        16#00000001 -> {disconnect, admin};
        16#00000002 -> {logoff, admin};
        16#00000003 -> {logoff, idle};
        16#00000004 -> {logoff, timelimit};
        16#00000005 -> {disconnect, other_conn};
        16#00000006 -> {error, out_of_memory};
        16#00000007 -> {denied, server};
        16#00000009 -> {denied, privileges};
        16#0000000A -> {denied, stale_creds};
        16#0000000B -> {disconnect, user_on_server};
        16#0000000C -> {logoff, user_on_server};
        16#0000000F -> {error, driver_timeout};
        16#00000010 -> {error, dwm_crash};
        16#00000011 -> {error, driver_crash};
        16#00000012 -> {error, driver_iface};
        16#00000017 -> {error, winlogon_crash};
        16#00000018 -> {error, csrss_crash};
        16#000010C9 -> {error, {sharedata, invalid_type}};
        16#000010CA -> {error, {sharecontrol, invalid_type}};
        16#000010CB -> {error, data_pdu_seq};
        16#000010CD -> {error, control_pdu_seq};
        16#000010CE -> {error, invalid_control_action};
        16#000010CF -> {error, {input_pdu, invalid}};
        16#000010D0 -> {error, {input_pdu, invalid_mouse}};
        16#000010D1 -> {error, invalid_refresh_rect};
        16#000010D2 -> {error, create_user_data_failed};
        16#000010D3 -> {error, connect_failed};
        16#000010D4 -> {error, {confirm_active, bad_shareid}};
        16#000010D5 -> {error, {confirm_active, bad_originator}};
        16#000010DE -> {error, {input_pdu, bad_length}};
        16#000010E0 -> {error, short_security_data};
        16#000010E1 -> {error, short_vchan_data};
        16#000010E2 -> {error, {sharedata, bad_length}};
        _ when (N >= 16#100) and (N =< 16#200) -> {license_error, N};
        _ when (N >= 16#400) and (N =< 16#500) -> {conn_broker_error, N};
        _ when (N >= 16#1000) and (N =< 16#2000) -> {error, N};
        _ -> {unknown, N}
    end,
    #ts_set_error_info{info = Info}.

decode_ts_control(Bin) ->
    <<Action:16/little, GrantId:16/little, ControlId:32/little>> = Bin,
    ActionAtom = case Action of 1 -> request; 2 -> granted; 3 -> detach; 4 -> cooperate end,
    #ts_control{action = ActionAtom, grantid = GrantId, controlid = ControlId}.

encode_ts_control(#ts_control{action = ActionAtom, grantid = GrantId, controlid = ControlId}) ->
    Action = case ActionAtom of request -> 1; granted -> 2; detach -> 3; cooperate -> 4 end,
    <<Action:16/little, GrantId:16/little, ControlId:32/little>>.

decode_ts_fontlist(_Bin) ->
    #ts_fontlist{}.

encode_ts_fontlist(#ts_fontlist{}) ->
    <<0:16, 0:16, 3:16/little, 50:16/little>>.

decode_ts_fontmap(_Bin) ->
    #ts_fontmap{}.

encode_ts_fontmap(#ts_fontmap{}) ->
    <<0:16, 0:16, 3:16/little, 4:16/little>>.

encode_ts_update(Rec) ->
    {Type, Inner} = case Rec of
        #ts_update_orders{} -> {0, encode_ts_update_orders(Rec)};
        #ts_update_bitmaps{} -> {1, encode_ts_update_bitmaps(Rec)}
    end,
    <<Type:16/little, Inner/binary>>.

encode_ts_monitor_layout(#ts_monitor_layout{monitors = Ms}) ->
    Count = length(Ms),
    iolist_to_binary([<<Count:32/little>>,
        [tsud:encode_monitor_def(M) || M <- Ms]]).

encode_ts_order_control_flags(Flags) ->
    Standard = 1,
    TypeChange = 1,
    Bounds = 0,
    Secondary = case lists:member(secondary, Flags) of true -> 1; _ -> 0 end,
    Delta = case lists:member(delta, Flags) of true -> 1; _ -> 0 end,
    ZeroBoundsDelta = 0,
    FieldZeros = 0,

    <<ControlFlags:8>> = <<FieldZeros:2, ZeroBoundsDelta:1, Delta:1, TypeChange:1, Bounds:1, Secondary:1, Standard:1>>,
    ControlFlags.

% encode_secondary_ts_order(Type, Flags, ExtraFlags, Inner) ->
%     ControlFlags = encode_ts_order_control_flags([secondary | Flags]),
%     % the -13 here is for historical reasons, see the spec
%     OrderLen = byte_size(Inner) + 6 - 13,
%     <<ControlFlags:8, OrderLen:16/little, ExtraFlags:16/little, Type:8, Inner/binary>>.

encode_primary_ts_order(Type, Fields, Flags, Inner) ->
    ControlFlags = encode_ts_order_control_flags(Flags),
    % primary drawing orders use the crazy bit string to identify
    % which params are being given and which are not
    FieldBits = erlang:ceil((length(Fields) + 1.0) / 8.0) * 8,
    Shortfall = FieldBits - length(Fields),
    FieldShort = lists:foldl(fun(Next, Bin) ->
        <<Next:1, Bin/bitstring>>
    end, <<>>, Fields),
    <<FieldN:FieldBits/big>> = <<0:Shortfall, FieldShort/bitstring>>,

    <<ControlFlags:8, Type:8, FieldN:FieldBits/little, Inner/binary>>.

encode_ts_order(#ts_order_opaquerect{flags = Flags, dest={X,Y}, size={W,H}, color={R,G,B}, bpp = Bpp}) ->
    Colour = case Bpp of
        24 ->
            <<R:8,G:8,B:8>>;
        16 ->
            <<C:16/big>> = <<(R bsr 3):5,(G bsr 2):6,(B bsr 3):5>>,
            <<C:24/little>>;
        15 ->
            <<C:16/big>> = <<0:1,(R bsr 3):5,(G bsr 3):5,(B bsr 3):5>>,
            <<C:24/little>>
    end,
    Inner = <<X:16/little-signed, Y:16/little-signed, W:16/little-signed,
              H:16/little-signed, Colour/bitstring>>,
    encode_primary_ts_order(16#0a, [1,1,1,1,1,1,1], Flags, Inner);

encode_ts_order(#ts_order_srcblt{flags = Flags, dest = {X1,Y1}, src = {X2, Y2}, size = {W,H}, rop = Rop}) ->
    Inner = <<X1:16/little-signed, Y1:16/little-signed, W:16/little-signed, H:16/little-signed, Rop:8, X2:16/little, Y2:16/little>>,
    encode_primary_ts_order(16#02, [1,1,1,1,1,1,1], Flags, Inner);

encode_ts_order(#ts_order_line{start = {X1,Y1}, finish = {X2,Y2}, flags = Flags, rop = Rop, color = {R,G,B}}) ->
    Inner = <<X1:16/little-signed, Y1:16/little-signed, X2:16/little-signed, Y2:16/little-signed, Rop:8, R:8, G:8, B:8>>,
    encode_primary_ts_order(16#09, [0,1,1,1,1,0,1,0,0,1], Flags, Inner).

encode_ts_update_orders(#ts_update_orders{orders = Orders}) ->
    OrdersBin = lists:foldl(fun(Next, Bin) ->
        Encode = encode_ts_order(Next),
        <<Bin/binary, Encode/binary>>
    end, <<>>, Orders),
    N = length(Orders),
    <<0:16, N:16/little, 0:16, OrdersBin/binary>>.

encode_ts_bitmap(#ts_bitmap{dest={X,Y}, size={W,H}, bpp=Bpp, comp_info=CompInfo, data=Data}) ->
    #ts_bitmap_comp_info{flags=CompFlags, scan_width=ScanWidth, full_size=FullSize} = CompInfo,
    Compressed = lists:member(compressed, CompFlags),
    ComprFlag = case Compressed of true -> 1; _ -> 0 end,
    NoComprFlag = case ScanWidth of undefined when Compressed -> 1; _ -> 0 end,
    <<Flags:16/big>> = <<0:5, NoComprFlag:1, 0:9, ComprFlag:1>>,
    X2 = X + W - 1,
    Y2 = Y + H - 1,
    Body = if
        Compressed and (NoComprFlag == 0) ->
            CompSize = byte_size(Data),
            CompHdr = <<0:16, CompSize:16/little, ScanWidth:16/little, FullSize:16/little>>,
            <<CompHdr/binary, Data/binary>>;
        true ->
            Data
    end,
    BodyLength = byte_size(Body),
    <<X:16/little-unsigned, Y:16/little-unsigned,
      X2:16/little-unsigned, Y2:16/little-unsigned,
      W:16/little-unsigned, H:16/little-unsigned,
      Bpp:16/little-unsigned,
      Flags:16/little-unsigned,
      BodyLength:16/little-unsigned, Body/binary>>.

encode_ts_update_bitmaps(#ts_update_bitmaps{bitmaps = Bitmaps}) ->
    N = length(Bitmaps),
    BitmapsBin = << <<(encode_ts_bitmap(B))/binary>> || B <- Bitmaps >>,
    true = (N < 1 bsl 16),
    true = (byte_size(BitmapsBin) < 1 bsl 16),
    <<N:16/little, BitmapsBin/binary>>.

decode_ts_inpevt(16#0000, Bin) ->
    <<_:16, Flags:16/little, Rest/binary>> = Bin,
    FlagSet = decode_ts_inpevt_sync_flags(Flags),
    {#ts_inpevt_sync{flags=FlagSet}, Rest};

decode_ts_inpevt(16#0004, Bin) ->
    <<Flags:16/little, KeyCode:16/little, _:16, Rest/binary>> = Bin,
    <<Release:1, AlreadyDown:1, _:5, Extended:1, _:8>> = <<Flags:16/big>>,
    Action = if Release == 1 -> up; true -> down end,
    FlagAtoms = if AlreadyDown == 1 -> [already_down]; true -> [] end ++
                if Extended == 1 -> [extended]; true -> [] end,
    {#ts_inpevt_key{code = kbd:process_scancode(KeyCode), action = Action, flags = FlagAtoms}, Rest};

decode_ts_inpevt(16#0005, Bin) ->
    <<Flags:16/little, KeyCode:16/little, _:16, Rest/binary>> = Bin,
    <<Release:1, _:15>> = <<Flags:16/big>>,
    Action = if Release == 1 -> up; true -> down end,
    {#ts_inpevt_unicode{code = KeyCode, action = Action}, Rest};

decode_ts_inpevt(16#8001, Bin) ->
    <<Flags:16/little, X:16/little, Y:16/little, Rest/binary>> = Bin,
    <<Down:1, Button3:1, Button2:1, Button1:1, Move:1, _:1, Wheel:1, WheelNegative:1, Clicks:8>> = <<Flags:16/big>>,
    if Wheel == 1 ->
        SignedClicks = if WheelNegative == 1 -> (0 - Clicks); true -> Clicks end,
        {#ts_inpevt_wheel{point = {X,Y}, clicks = SignedClicks}, Rest};
    true ->
        Action = if Move == 1 -> move; Down == 1 -> down; true -> up end,
        Buttons = if Button3 == 1 -> [3]; true -> [] end ++
                  if Button2 == 1 -> [2]; true -> [] end ++
                  if Button1 == 1 -> [1]; true -> [] end,
        {#ts_inpevt_mouse{point = {X,Y}, action = Action, buttons = Buttons}, Rest}
    end;

decode_ts_inpevt(16#8002, Bin) ->
    <<Flags:16/little, X:16/little, Y:16/little, Rest/binary>> = Bin,
    <<Down:1, _:13, Button5:1, Button4:1>> = <<Flags:16/big>>,
    Action = if Down == 1 -> down; true -> up end,
    Buttons = if Button4 == 1 -> [4]; true -> [] end ++
              if Button5 == 1 -> [5]; true -> [] end,
    {#ts_inpevt_mouse{point = {X,Y}, action = Action, buttons = Buttons}, Rest};

decode_ts_inpevt(_, _) ->
    error(not_implemented).

decode_ts_inpevts(_, <<>>) -> [];
decode_ts_inpevts(0, _) -> [];
decode_ts_inpevts(N, Bin) ->
    <<_Time:32/little, Type:16/little, Rest/binary>> = Bin,
    {Next, Rem} = decode_ts_inpevt(Type, Rest),
    [Next | decode_ts_inpevts(N - 1, Rem)].

padding_only(Bin) ->
    Sz = bit_size(Bin),
    <<0:Sz>> = Bin.

decode_ts_shutdown(Bin) ->
    padding_only(Bin),
    #ts_shutdown{}.

decode_ts_shutdown_denied(Bin) ->
    padding_only(Bin),
    #ts_shutdown_denied{}.

decode_ts_input(Bin) ->
    <<N:16/little, _:16, Evts/binary>> = Bin,
    #ts_input{events = decode_ts_inpevts(N, Evts)}.

decode_ts_ad(_Fl, <<HdrLen:8, Rest/binary>>) ->
    HdrLen1 = HdrLen - 1,
    <<Hdr:HdrLen1/binary, _Data/binary>> = Rest,
    case Hdr of
        <<0, Seq:16/little, 16#0001:16/little>> ->
            #rdp_rtt{seq = Seq, type = connseq};
        <<0, Seq:16/little, 16#1001:16/little>> ->
            #rdp_rtt{seq = Seq, type = postconnect};
        <<1, Seq:16/little, 16#0000:16/little>> ->
            #rdp_rtt{seq = Seq}
    end.

encode_ts_ad(#ts_autodetect_req{pdu = #rdp_rtt{seq = Seq, type = Type}}) ->
    TypeInt = case Type of
        postconnect -> 16#1001;
        connseq -> 16#0001
    end,
    Hdr = <<0, Seq:16/little, TypeInt:16/little>>,
    <<(byte_size(Hdr)+1):8, Hdr/binary>>;

encode_ts_ad(#ts_autodetect_resp{pdu = #rdp_rtt{seq = Seq}}) ->
    Hdr = <<1, Seq:16/little, 16#0000:16/little>>,
    <<(byte_size(Hdr)+1):8, Hdr/binary>>.

encode_basic(Rec) ->
    SecFlags = element(2, Rec),
    {Type, Inner} = case Rec of
        #ts_security{} -> {security, encode_ts_security(Rec)};
        #ts_license_vc{} -> {license, encode_ts_license_vc(Rec)};
        #ts_heartbeat{} -> {heartbeat, encode_ts_heartbeat(Rec)};
        #ts_info{} -> {info, encode_ts_info(Rec)};
        #ts_autodetect_req{} -> {autodetect_req, encode_ts_ad(Rec)};
        #ts_autodetect_resp{} -> {autodetect_rsp, encode_ts_ad(Rec)}
    end,
    Flags = encode_sec_flags({Type, SecFlags}),
    {ok, <<Flags:16/little, 0:16, Inner/binary>>}.

decode_basic(Bin) ->
    case Bin of
        <<Flags:16/little, _:16, Rest/binary>> ->
            case (catch decode_sec_flags(Flags)) of
                {'EXIT', Why} -> {error, {badpacket, Why}};
                {security, Fl} -> decode_ts_security(Fl, Rest);
                {info, Fl} -> decode_ts_info(Fl, Rest);
                {heartbeat, Fl} -> decode_ts_heartbeat(Fl, Rest);
                {autodetect_req, Fl} ->
                    {ok, #ts_autodetect_req{pdu = decode_ts_ad(Fl, Rest)}};
                {autodetect_rsp, Fl} ->
                    {ok, #ts_autodetect_resp{pdu = decode_ts_ad(Fl, Rest)}};
                {Type, Fl} ->
                    _ = lager:warning("unhandled basic: ~p, flags = ~p", [Type, Fl]),
                    {error, badpacket}
            end;
        _ ->
            {error, badpacket}
    end.

encode_ts_security(#ts_security{random = Random}) ->
    Len = byte_size(Random),
    <<Len:32/little, Random/binary>>.

encode_ts_license_vc(#ts_license_vc{}) ->
    Inner = <<16#7:32/little, 16#2:32/little, 16#04:16/little, 0:16>>,
    Len = byte_size(Inner) + 4,
    % this was 16#83 before?
    <<16#ff, 16#03, Len:16/little, Inner/binary>>.

decode_ts_security(Fl, Bin) ->
    case Bin of
        <<Length:32/little, Rest/binary>> ->
            RealSize = byte_size(Rest),
            if Length == RealSize ->
                {ok, #ts_security{secflags = Fl, random = Rest}};
            true ->
                {error, badlength}
            end;
        _ ->
            {error, badpacket}
    end.

encode_ts_heartbeat(#ts_heartbeat{period = Period, warning = Warn, reconnect = Recon}) ->
    <<0, Period, Warn, Recon>>.

decode_ts_heartbeat(Fl, Bin) ->
    case Bin of
        <<_, Period, Warn, Recon>> ->
            {ok, #ts_heartbeat{secflags = Fl, period = Period, warning = Warn, reconnect = Recon}};
        _ ->
            {error, badpacket}
    end.

decode_ts_date(Bin) ->
    <<Year:16/little, Month:16/little, DoW:16/little, Nth:16/little, Hour:16/little, Min:16/little, Sec:16/little, Milli:16/little>> = Bin,
    {{Year, Month, DoW, Nth}, {Hour, Min, Sec, Milli}}.

ts_string_to_list(Flags, Str0) ->
    Str1 = case lists:member(unicode, Flags) of
        true -> unicode:characters_to_binary(Str0, {utf16, little}, utf8);
        false -> unicode:characters_to_binary(Str0, latin1, utf8)
    end,
    [Str2 | _] = binary:split(Str1, <<0>>),
    unicode:characters_to_list(Str2, utf8).

decode_ts_ext_info(Bin0, SoFar0 = #ts_info{}) ->
    maybe([
        fun(Bin, SoFar = #ts_info{flags = Fl}) ->
            case Bin of
                <<Af:16/little, Len:16/little, AddrStringZero:Len/binary, Rest/binary>> ->
                    case Af of
                        16#00 ->
                            {continue, [Rest, SoFar]};
                        16#02 ->
                            AddrString = ts_string_to_list(Fl, AddrStringZero),
                            {ok, IP} = inet:parse_ipv4_address(AddrString),
                            {continue, [Rest, SoFar#ts_info{client_address = IP}]};
                        16#17 ->
                            AddrString = ts_string_to_list(Fl, AddrStringZero),
                            {ok, IP} = inet:parse_ipv6_address(AddrString),
                            {continue, [Rest, SoFar#ts_info{client_address = IP}]};
                        _ ->
                            _ = lager:warning("unhandled client address family: ~p (length ~p)", [Af, Len]),
                            {continue, [Rest, SoFar]}
                    end;
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<Len:16/little, ClientDir:Len/binary, Rest/binary>> ->
                    {continue, [Rest, SoFar#ts_info{client_dir = ClientDir}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<Bias:32/signed-little, NameBin:64/binary, DstEndBin:16/binary, _StdBias:32/signed-little, DstNameBin:64/binary, DstStartBin:16/binary, DstBias:32/signed-little, Rest/binary>> ->
                    DstEnd = decode_ts_date(DstEndBin),
                    DstStart = decode_ts_date(DstStartBin),
                    [Name | _] = binary:split(NameBin, <<0, 0>>),
                    [DstName | _] = binary:split(DstNameBin, <<0, 0>>),
                    Tz = #ts_timezone{bias = Bias, name = Name, dst_name = DstName, dst_bias = DstBias, dst_start = DstStart, dst_end = DstEnd},
                    {continue, [Rest, SoFar#ts_info{timezone = Tz}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<SessionId:32/little, Rest/binary>> ->
                    {continue, [Rest, SoFar#ts_info{session_id = SessionId}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<PerfFlags:32/little, Rest/binary>> ->
                    FlagSet = decode_ts_info_perf_flags(PerfFlags),
                    {continue, [Rest, SoFar#ts_info{perf_flags = FlagSet}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<Len:16/little, Cookie:Len/binary, Rest/binary>> ->
                    {continue, [Rest, SoFar#ts_info{reconnect_cookie = Cookie}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<_:16, _:16, Len:16/little, DynTzName:Len/binary, Rest/binary>> ->
                    {continue, [Rest, SoFar#ts_info{dynamic_dst = DynTzName}]};
                _ ->
                    {return, {ok, SoFar}}
            end
        end,
        fun(Bin, SoFar) ->
            case Bin of
                <<DynDstDisabled:16/little, Rest/binary>> when DynDstDisabled == 0 ->
                    {continue, [Rest, SoFar#ts_info{flags = [dynamic_dst | SoFar#ts_info.flags]}]};
                <<_:16, Rest/binary>> ->
                    {continue, [Rest, SoFar]}
            end
        end,
        fun(_Bin, SoFar) ->
            {return, {ok, SoFar}}
        end
    ], [Bin0, SoFar0]).

decode_ts_info(Fl, Bin) ->
    case Bin of
        <<CodePage:32/little, Flags:32/little, RawDomainLen:16/little, RawUserNameLen:16/little, RawPasswordLen:16/little, RawShellLen:16/little, RawWorkDirLen:16/little, Rest/binary>> ->

            FlagList = decode_ts_info_flags(Flags),
            <<_:19, CompLevel:4, _:9>> = <<Flags:32/big>>,

            CompLevelAtom = case CompLevel of
                16#0 -> '8k';
                16#1 -> '64k';
                16#2 -> 'rdp6';
                16#3 -> 'rdp61';
                16#7 -> 'rdp8';
                _ -> CompLevel
            end,

            NullSize = case lists:member(unicode, FlagList) of
                true -> 2;
                false -> 1
            end,
            DomainLen = RawDomainLen + NullSize,
            UserNameLen = RawUserNameLen + NullSize,
            PasswordLen = RawPasswordLen + NullSize,
            ShellLen = RawShellLen + NullSize,
            WorkDirLen = RawWorkDirLen + NullSize,

            case Rest of
                <<Domain:DomainLen/binary, UserName:UserNameLen/binary, Password:PasswordLen/binary, Shell:ShellLen/binary, WorkDir:WorkDirLen/binary, ExtraInfo/binary>> ->
                    SoFar = #ts_info{secflags = Fl,
                                     codepage = CodePage,
                                     flags = FlagList,
                                     compression = CompLevelAtom,
                                     domain = Domain,
                                     username = UserName,
                                     password = Password,
                                     shell = Shell,
                                     workdir = WorkDir,
                                     extra = ExtraInfo},
                    case ExtraInfo of
                        <<>> ->
                            {ok, SoFar};
                        _ ->
                            decode_ts_ext_info(ExtraInfo, SoFar)
                    end;
                _ ->
                    {error, badlength}
            end;
        _ ->
            {error, badpacket}
    end.

maybe_bin(B, _) when is_binary(B) -> B;
maybe_bin(undefined, 1) -> <<0, 0>>;
maybe_bin(undefined, 0) -> <<0>>.

encode_ts_info(#ts_info{codepage = CodePage, flags = FlagAtoms, compression = CompLevelAtom, domain = MaybeDomain, username = MaybeUserName, password = MaybePassword, shell = MaybeShell, workdir = MaybeWorkDir, extra = MaybeExtraInfo}) ->
    Unicode = case lists:member(unicode, FlagAtoms) of true -> 1; _ -> 0 end,
    Domain = maybe_bin(MaybeDomain, Unicode),
    UserName = maybe_bin(MaybeUserName, Unicode),
    Password = maybe_bin(MaybePassword, Unicode),
    Shell = maybe_bin(MaybeShell, Unicode),
    WorkDir = maybe_bin(MaybeWorkDir, Unicode),
    ExtraInfo = maybe_bin(MaybeExtraInfo, Unicode),

    CompLevel = case CompLevelAtom of
        '8k' -> 16#0;
        '64k' -> 16#1;
        'rdp6' -> 16#2;
        'rdp61' -> 16#3;
        'rdp8' -> 16#7;
        I when is_integer(I) -> I
    end,

    <<BeforeComp:19/bitstring, _:4, AfterComp:9/bitstring>> = encode_ts_info_flags_bin(FlagAtoms),
    <<Flags:32/big>> = <<BeforeComp/bitstring, CompLevel:4, AfterComp/bitstring>>,

    NullSize = if Unicode == 1 -> 2; true -> 1 end,
    DomainLen = byte_size(Domain) - NullSize,
    UserNameLen = byte_size(UserName) - NullSize,
    PasswordLen = byte_size(Password) - NullSize,
    ShellLen = byte_size(Shell) - NullSize,
    WorkDirLen = byte_size(WorkDir) - NullSize,

    <<CodePage:32/little, Flags:32/little, DomainLen:16/little, UserNameLen:16/little, PasswordLen:16/little, ShellLen:16/little, WorkDirLen:16/little, Domain/binary, UserName/binary, Password/binary, Shell/binary, WorkDir/binary, ExtraInfo/binary>>.

maybe([], _Args) -> error(no_return);
maybe([Fun | Rest], Args) ->
    case apply(Fun, Args) of
        {continue, NewArgs} ->
            maybe(Rest, NewArgs);
        {return, Value} ->
            Value
    end.

