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

-module(x224).

-include("x224.hrl").

-export([encode/1, decode/1, pretty_print/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(PDU_CR, 2#1110).
-define(PDU_CC, 2#1101).
-define(PDU_DR, 2#1000).
-define(PDU_AK, 2#0110).
-define(PDU_DT, 2#1111).

-define(RDP_NEGREQ, 16#01).
-define(RDP_NEGRSP, 16#02).
-define(RDP_NEGFAIL, 16#03).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(x224_cr);
?pp(x224_cc);
?pp(x224_dt);
?pp(x224_dr);
pretty_print(_, _) ->
    no.

-spec encode(Record :: term()) -> {ok, binary()} | {error, term()}.
encode(Record) ->
    case Record of
        #x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie, rdp_protocols = Protocols} ->
            Head = <<?PDU_CR:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,
            CookiePart = if is_binary(Cookie) and not (Cookie =:= <<>>) ->
                <<Cookie/binary, 16#0d0a:16/big>>;
            is_list(Cookie) and not (Cookie =:= []) ->
                Bin = list_to_binary(Cookie),
                <<Bin/binary, 16#0d0a:16/big>>;
            true ->
                <<>>
            end,

            Prots = rdpp:encode_protocol_flags(Protocols),
            RdpPart = <<?RDP_NEGREQ:8, 0:8, 8:16/little, Prots:32/little>>,

            LI = byte_size(Head) + byte_size(CookiePart) + byte_size(RdpPart),
            {ok, <<LI:8, Head/binary, CookiePart/binary, RdpPart/binary>>};

        #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status = error, rdp_error = Error} ->
            Head = <<?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,
            Code = case Error of
                ssl_required -> 16#01;
                ssl_not_allowed -> 16#02;
                cert_not_on_server -> 16#03;
                bad_flags -> 16#04;
                credssp_required -> 16#05;
                ssl_with_user_auth_required -> 16#06;
                _ -> 0
            end,
            RdpPart = <<?RDP_NEGFAIL:8, 0:8, 8:16/little, Code:32/little>>,

            LI = byte_size(Head) + byte_size(RdpPart),
            {ok, <<LI:8, Head/binary, RdpPart/binary>>};

        #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status=ok, rdp_flags = Flags, rdp_selected = Protocols} ->
            Head = <<?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,

            Prots = rdpp:encode_protocol_flags(Protocols),

            DynVcGfx = case lists:member(dynvc_gfx, Flags) of true -> 1; _ -> 0 end,
            ExtData = case lists:member(extdata, Flags) of true -> 1; _ -> 0 end,
            NegRspRsvd = case lists:member(negrsp_rsvd, Flags) of true -> 1; _ -> 0 end,
            RestrictedAdmin = case lists:member(restricted_admin, Flags) of true -> 1; _ -> 0 end,
            CredGuard = case lists:member(credguard, Flags) of true -> 1; _ -> 0 end,
            <<Flags2:8>> = <<0:3, CredGuard:1, RestrictedAdmin:1, NegRspRsvd:1, DynVcGfx:1, ExtData:1>>,

            RdpPart = <<?RDP_NEGRSP:8, Flags2:8, 8:16/little, Prots:32/little>>,

            LI = byte_size(Head) + byte_size(RdpPart),
            {ok, <<LI:8, Head/binary, RdpPart/binary>>};

        #x224_dt{roa = ROA, eot = EOT, tpdunr = TpduNr, data = Data} ->
            Head = <<?PDU_DT:4, 0:3, ROA:1, EOT:1, TpduNr:7>>,
            LI = byte_size(Head),
            {ok, <<LI:8, Head/binary, Data/binary>>};

        #x224_dr{dst = DstRef, src = SrcRef, reason = Error} ->
            Reason = case Error of
                not_specified -> 0;
                congestion -> 1;
                not_attached -> 2;
                address_unknown -> 3;
                _ -> 0
            end,
            Head = <<?PDU_DR:4, 0:4, DstRef:16/big, SrcRef:16/big, Reason:8>>,
            LI = byte_size(Head),
            {ok, <<LI:8, Head/binary>>};

        _ ->
            {error, bad_x224}
    end.

-spec decode(Data :: binary()) -> {ok, term()} | {error, term()}.
decode(Data) ->
    case Data of
        <<_LI:8, ?PDU_CR:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, _ExtFmts:1, _ExFlow:1, Rest/binary>> ->
            {Cookie, RdpData} = case binary:match(Rest, <<16#0d0a:16/big>>) of
                {Pos, _} ->
                    <<Token:Pos/binary-unit:8, 16#0d0a:16/big, Rem/binary>> = Rest,
                    {Token, Rem};
                _ ->
                    {none, Rest}
            end,
            case RdpData of
                <<?RDP_NEGREQ:8, _Flags:8, 8:16/little, Protocols:32/little, _/binary>> ->
                    Prots = rdpp:decode_protocol_flags(Protocols),
                    {ok, #x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie, rdp_protocols = Prots}};
                _ ->
                    {ok, #x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie}}
            end;

        <<_LI:8, ?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, _ExtFmts:1, _ExFlow:1, Rest/binary>> ->
            case Rest of
                <<?RDP_NEGRSP:8, Flags:8, _Length:16/little, Selected:32/little>> ->
                    <<0:3, CredGuard:1, RestrictedAdmin:1, NegRsp:1, DynVcGfx:1, ExtData:1>> = <<Flags:8>>,
                    Flags2 = if DynVcGfx == 1 -> [dynvc_gfx]; true -> [] end ++
                             if ExtData == 1 -> [extdata]; true -> [] end ++
                             if NegRsp == 1 -> [negrsp_rsvd]; true -> [] end ++
                             if RestrictedAdmin == 1 -> [restricted_admin]; true -> [] end ++
                             if CredGuard == 1 -> [credguard]; true -> [] end,

                    Prots = rdpp:decode_protocol_flags(Selected),
                    {ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_flags = Flags2, rdp_selected = Prots}};

                <<?RDP_NEGFAIL:8,  _Flags:8, _Length:16/little, Code:32/little>> ->
                    Error = case Code of
                        16#01 -> ssl_required;
                        16#02 -> ssl_not_allowed;
                        16#03 -> cert_not_on_server;
                        16#04 -> bad_flags;
                        16#05 -> credssp_required;
                        16#06 -> ssl_with_user_auth_required;
                        _ -> unknown
                    end,
                    {ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status = error, rdp_error = Error}};

                _ ->
                    {ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_selected = []}}
            end;

        <<LI:8, ?PDU_DT:4, 0:3, ROA:1, EOT:1, TpduNr:7, Rest/binary>> when LI == 2 ->
            {ok, #x224_dt{roa = ROA, eot = EOT, tpdunr = TpduNr, data = Rest}};

        <<_LI:8, ?PDU_DR:4, 0:4, DstRef:16/big, SrcRef:16/big, Reason:8, _Rest/binary>> ->
            Error = case Reason of
                0 -> not_specified;
                1 -> congestion;
                2 -> not_attached;
                3 -> address_unknown;
                _ -> unknown
            end,
            {ok, #x224_dr{dst = DstRef, src = SrcRef, reason = Error}};

        _ ->
            {error, bad_x224}
    end.

-ifdef(TEST).

dec_hex_string([]) -> <<>>;
dec_hex_string([A | Rest]) when (A >= $0) and (A =< $9) ->
    <<(A - $0):4, (dec_hex_string(Rest))/bitstring>>;
dec_hex_string([A | Rest]) when (A >= $a) and (A =< $f) ->
    <<(A - $a + 10):4, (dec_hex_string(Rest))/bitstring>>;
dec_hex_string([A | Rest]) when (A == 32) or (A == 10) ->
    dec_hex_string(Rest).

spec_4_1_1_test() ->
    Pkt = dec_hex_string("27 e0 00 00 00 00 00 43 6f 6f 6b
        69 65 3a 20 6d 73 74 73 68 61 73 68
        3d 65 6c 74 6f 6e 73 0d 0a
        01 00 08 00 00 00 00 00"),
    ?assertMatch({ok, #x224_cr{
        src = 0, dst = 0, rdp_cookie = <<"Cookie: mstshash=eltons">>,
        rdp_protocols = []
        }}, decode(Pkt)).

spec_4_1_2_test() ->
    Pkt = dec_hex_string("0e d0 00 00 12 34 00
        02 00 08 00 00 00 00 00"),
    ?assertMatch({ok, #x224_cc{
        src = 16#1234, dst = 0, rdp_flags = [], rdp_selected = [],
        rdp_status = ok
        }}, decode(Pkt)).

spec_4_1_3_test() ->
    Pkt = dec_hex_string("02 f0 80 12 34"),
    ?assertMatch({ok, #x224_dt{data = <<16#12, 16#34>>}}, decode(Pkt)).

encode_decode_test() ->
    Pkt = #x224_cr{src = 1, dst = 2,
        rdp_cookie = <<"foo">>, rdp_protocols = [ssl]},
    {ok, Bin} = encode(Pkt),
    ?assertMatch({ok, Pkt}, decode(Bin)),

    Pkt2 = #x224_cc{src = 2, dst = 1,
        rdp_status = error, rdp_error = ssl_required},
    {ok, Bin2} = encode(Pkt2),
    ?assertMatch({ok, Pkt2}, decode(Bin2)).

decode_fail_test() ->
    Pkt = dec_hex_string("0a f0 80 12 34"),
    ?assertMatch({error, _}, decode(Pkt)),

    Pkt2 = dec_hex_string("0e f0 ff ff 22 34 00
        02 00 08 00 00 00 00 00"),
    ?assertMatch({error, _}, decode(Pkt2)).

-endif.
