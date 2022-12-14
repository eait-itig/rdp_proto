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

-module(cliprdr).

-include("cliprdr.hrl").

-compile([{parse_transform, bitset_parse_transform}]).

-export([pretty_print/1]).
-export([encode/1, decode/2]).

-export_type([cliprdr_cap/0, format/0]).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(cliprdr_caps);
?pp(cliprdr_format_list);
?pp(cliprdr_cap_general);
?pp(cliprdr_monitor_ready);
?pp(cliprdr_format_resp);
?pp(cliprdr_data_req);
?pp(cliprdr_data_resp);
pretty_print(_, _) ->
    no.

-bitset({msg_flags, [{skip, 13}, ascii_names, fail, ok]}).

-type cliprdr_pdu() :: #cliprdr_monitor_ready{} | #cliprdr_format_list{} |
    #cliprdr_caps{} | #cliprdr_format_resp{}.

-spec encode(cliprdr_pdu()) -> binary() | {error, term()}.

encode(#cliprdr_monitor_ready{flags = Flags}) ->
    encode(16#0001, Flags, <<>>);

encode(#cliprdr_format_list{flags = Flags, formats = Formats}) ->
    Data = iolist_to_binary([encode_long_format(F) || F <- Formats]),
    encode(16#0002, Flags, Data);

encode(#cliprdr_caps{flags = Flags, caps = Caps}) ->
    NSets = length(Caps),
    CapSets = iolist_to_binary([encode_cap(C) || C <- Caps]),
    Data = <<NSets:16/little, 0:16, CapSets/binary>>,
    encode(16#0007, Flags, Data);

encode(#cliprdr_format_resp{flags = Flags}) ->
    encode(16#0003, Flags, <<>>);

encode(#cliprdr_data_req{flags = Flags, format = Fmt}) ->
    Id = case Fmt of
        text -> 1;
        bitmap -> 2;
        metafile -> 3;
        sylk -> 4;
        dif -> 5;
        tiff -> 6;
        oemtext -> 7;
        dib -> 8;
        palette -> 9;
        pendata -> 10;
        riff -> 11;
        wave -> 12;
        unicode -> 13;
        enh_metafile -> 14;
        hdrop -> 15;
        locale -> 16;
        I when is_integer(I) -> I
    end,
    encode(16#0004, Flags, <<Id:32/little>>);

encode(#cliprdr_data_resp{flags = Flags, data = Data}) ->
    encode(16#0005, Flags, Data);

encode(_) -> error(bad_record).

encode(Type, FlagList, Data) ->
    MsgFlags = encode_msg_flags(FlagList),
    Len = byte_size(Data),
    <<Type:16/little, MsgFlags:16/little, Len:32/little, Data/binary>>.

-type cliprdr_cap() :: #cliprdr_cap_general{}.
-spec decode(binary(), [cliprdr_cap()]) -> {ok, cliprdr_pdu()} | {error, term()}.

decode(<<MsgType:16/little, MsgFlags:16/little, Len:32/little, Data:Len/binary, Pad/binary>>, Caps) ->
    PadLen = 8 * byte_size(Pad),
    case Pad of
        <<0:PadLen>> ->
            MsgFlagList = decode_msg_flags(MsgFlags),
            decode(MsgType, MsgFlagList, Caps, Data);
        _ ->
            {error, bad_packet_padding}
    end;
decode(_, _) ->
    {error, bad_packet}.

decode(16#0001, MsgFlags, _Caps, _Data) ->
    {ok, #cliprdr_monitor_ready{flags = MsgFlags}};

decode(16#0002, MsgFlags, Caps, Data) ->
    UseLongFormat = case lists:keyfind(cliprdr_cap_general, 1, Caps) of
        #cliprdr_cap_general{flags = F} -> lists:member(long_names, F);
        _ -> false
    end,
    Formats = if
        UseLongFormat -> decode_long_format(Data);
        not UseLongFormat -> decode_short_format(Data)
    end,
    {ok, #cliprdr_format_list{flags = MsgFlags, formats = Formats}};

decode(16#0003, MsgFlags, _Caps, _Data) ->
    {ok, #cliprdr_format_resp{flags = MsgFlags}};

decode(16#0004, MsgFlags, _Caps, Data) ->
    <<Id:32/little>> = Data,
    Fmt = case Id of
        1 -> text;
        2 -> bitmap;
        3 -> metafile;
        4 -> sylk;
        5 -> dif;
        6 -> tiff;
        7 -> oemtext;
        8 -> dib;
        9 -> palette;
        10 -> pendata;
        11 -> riff;
        12 -> wave;
        13 -> unicode;
        14 -> enh_metafile;
        15 -> hdrop;
        16 -> locale;
        I when is_integer(I) -> I
    end,
    {ok, #cliprdr_data_req{flags = MsgFlags, format = Fmt}};

decode(16#0005, MsgFlags, _Caps, Data) ->
    {ok, #cliprdr_data_resp{flags = MsgFlags, data = Data}};

decode(16#0007, MsgFlags, _Caps, Data) ->
    <<NSets:16/little, _:16, SetsBin/binary>> = Data,
    Caps = decode_caps_set(SetsBin, NSets),
    {ok, #cliprdr_caps{flags = MsgFlags, caps = Caps}};

decode(MsgType, _, _, _) ->
    {error, {unknown_type, MsgType}}.

-type format() :: text | bitmap | metafile | sylk | dif | tiff | oemtext |
    dib | palette | pendata | riff | wave | unicode | enh_metafile | hdrop |
    locale | {Id :: integer(), Name :: string()}.

-spec decode_short_format(binary()) -> [format()].
decode_short_format(<<>>) -> [];
decode_short_format(<<Id:32/little, NameBin:32/binary, Rest/binary>>) ->
    Name0 = unicode:characters_to_list(NameBin, {utf16, little}),
    Name = lists:takewhile(fun (C) -> C > 0 end, Name0),
    Fmt = case {Id, Name} of
        {1, _} -> text;
        {2, _} -> bitmap;
        {3, _} -> metafile;
        {4, _} -> sylk;
        {5, _} -> dif;
        {6, _} -> tiff;
        {7, _} -> oemtext;
        {8, _} -> dib;
        {9, _} -> palette;
        {10, _} -> pendata;
        {11, _} -> riff;
        {12, _} -> wave;
        {13, _} -> unicode;
        {14, _} -> enh_metafile;
        {15, _} -> hdrop;
        {16, _} -> locale;
        {_, _} -> {Id, Name}
    end,
    [Fmt | decode_short_format(Rest)].

-spec decode_long_format(binary()) -> [format()].
decode_long_format(<<>>) -> [];
decode_long_format(<<Id:32/little, Rest/binary>>) ->
    {Name0, Rem0} = split_zero16(Rest),
    Name = unicode:characters_to_list(Name0, {utf16, little}),
    Fmt = case {Id, Name} of
        {1, _} -> text;
        {2, _} -> bitmap;
        {3, _} -> metafile;
        {4, _} -> sylk;
        {5, _} -> dif;
        {6, _} -> tiff;
        {7, _} -> oemtext;
        {8, _} -> dib;
        {9, _} -> palette;
        {10, _} -> pendata;
        {11, _} -> riff;
        {12, _} -> wave;
        {13, _} -> unicode;
        {14, _} -> enh_metafile;
        {15, _} -> hdrop;
        {16, _} -> locale;
        {_, _} -> {Id, Name}
    end,
    [Fmt | decode_long_format(Rem0)].

split_zero16(Bin) -> split_zero16(<<>>, Bin).
split_zero16(SoFar, <<>>) -> {SoFar, <<>>};
split_zero16(SoFar, <<0, 0, Rest/binary>>) -> {SoFar, Rest};
split_zero16(SoFar, <<A, B, Rest/binary>>) ->
    split_zero16(<<SoFar/binary, A, B>>, Rest).

-spec encode_long_format(format()) -> binary().
encode_long_format(text) -> <<1:32/little, 0, 0>>;
encode_long_format(bitmap) -> <<2:32/little, 0, 0>>;
encode_long_format(metafile) -> <<3:32/little, 0, 0>>;
encode_long_format(sylk) -> <<4:32/little, 0, 0>>;
encode_long_format(dif) -> <<5:32/little, 0, 0>>;
encode_long_format(tiff) -> <<6:32/little, 0, 0>>;
encode_long_format(oemtext) -> <<7:32/little, 0, 0>>;
encode_long_format(dib) -> <<8:32/little, 0, 0>>;
encode_long_format(palette) -> <<9:32/little, 0, 0>>;
encode_long_format(pendata) -> <<10:32/little, 0, 0>>;
encode_long_format(riff) -> <<11:32/little, 0, 0>>;
encode_long_format(wave) -> <<12:32/little, 0, 0>>;
encode_long_format(unicode) -> <<13:32/little, 0, 0>>;
encode_long_format(enh_metafile) -> <<14:32/little, 0, 0>>;
encode_long_format(hdrop) -> <<15:32/little, 0, 0>>;
encode_long_format(locale) -> <<16:32/little, 0, 0>>;
encode_long_format({Id, Name}) ->
    NameBin = unicode:characters_to_binary(Name, {utf16, little}),
    <<Id:32/little, NameBin/binary, 0, 0>>.

-bitset({gencap_flags, [{skip, 26}, hugefile, locking, no_file_paths, files,
    long_names, skip]}).

decode_caps_set(_, 0) -> [];
decode_caps_set(<<>>, N) when N > 0 -> error({expected_cap_set, N});
decode_caps_set(<<Type:16/little, Len:16/little, Rest/binary>>, N) ->
    DataLen = Len - 4,
    <<Data:DataLen/binary, Rem/binary>> = Rest,
    case Type of
        16#01 ->
            <<Version:32/little, Flags:32/little>> = Data,
            FlagSet = decode_gencap_flags(Flags),
            [#cliprdr_cap_general{flags = FlagSet, version = Version} |
                decode_caps_set(Rem, N - 1)];
        _ -> error({unknown_cap_type, Type})
    end.

encode_cap(#cliprdr_cap_general{flags = FlagList, version = Version}) ->
    Flags = encode_gencap_flags(FlagList),
    Data = <<Version:32/little, Flags:32/little>>,
    Len = byte_size(Data) + 4,
    <<16#01:16/little, Len:16/little, Data/binary>>.

