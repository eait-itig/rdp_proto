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

-module(mcsgcc).

-compile([{parse_transform, lager_transform}]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("mcsgcc.hrl").
-include("mcsp.hrl").
-include("gccp.hrl").

-export([encode_ci/1, decode_ci/1]).
-export([decode_cr/1, encode_cr/1]).
-export([decode_dpdu/1, encode_dpdu/1]).

-export([decode/1, encode/1]).
-export([pretty_print/1]).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(mcs_ci);
?pp(mcs_cr);
?pp(mcs_edr);
?pp(mcs_aur);
?pp(mcs_auc);
?pp(mcs_cjr);
?pp(mcs_cjc);
?pp(mcs_tir);
?pp(mcs_data);
?pp(mcs_srv_data);
?pp(mcs_dpu);
pretty_print(_, _) ->
    no.

decode_try_methods(Bin, []) -> {error, {nomethod, Bin}};
decode_try_methods(Bin, Methods) ->
    [Method|Rest] = Methods,
    case ?MODULE:Method(Bin) of
        {ok, Rec} -> {ok, Rec};
        _Error ->
            %lager:debug("tried: ~p, got: ~p\n", [Method, Error]),
            decode_try_methods(Bin, Rest)
    end.

decode(Bin) ->
    Methods = [decode_dpdu, decode_ci, decode_cr],
    decode_try_methods(Bin, Methods).

encode(#mcs_ci{} = Rec) -> encode_ci(Rec);
encode(#mcs_cr{} = Rec) -> encode_cr(Rec);
encode(#mcs_edr{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_tic{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_cjc{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_auc{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_data{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_srv_data{} = Rec) -> encode_dpdu(Rec);
encode(#mcs_dpu{} = Rec) -> encode_dpdu(Rec);
encode(_) -> {error, bad_mcsgcc}.

padding_only(Bin) ->
    Sz = bit_size(Bin),
    <<0:Sz>> = Bin.

decode_dpdu(sendDataRequest, #'SendDataRequest'{initiator = User,
                                                channelId = Channel,
                                                dataPriority = Priority,
                                                userData = Data}) ->
    {ok, #mcs_data{user = User, channel = Channel, priority = Priority,
                   data = Data}};

decode_dpdu(sendDataIndication, #'SendDataIndication'{initiator = User,
                                                      channelId = Channel,
                                                      dataPriority = Priority,
                                                      userData = Data}) ->
    {ok, #mcs_srv_data{user = User, channel = Channel, priority = Priority,
                       data = Data}};

decode_dpdu(erectDomainRequest, #'ErectDomainRequest'{subHeight = Height,
                                                      subInterval = Interval}) ->
    {ok, #mcs_edr{height = Height, interval = Interval}};

decode_dpdu(attachUserRequest, #'AttachUserRequest'{}) ->
    {ok, #mcs_aur{}};

decode_dpdu(attachUserConfirm, #'AttachUserConfirm'{result = Result,
                                                    initiator = UserId}) ->
    {ok, #mcs_auc{status = Result, user = UserId}};

decode_dpdu(channelJoinRequest, #'ChannelJoinRequest'{initiator = UserId,
                                                      channelId = Channel}) ->
    {ok, #mcs_cjr{user = UserId, channel = Channel}};

decode_dpdu(channelJoinConfirm, #'ChannelJoinConfirm'{result = Result,
                                                      initiator=UserId,
                                                      requested=Channel}) ->
    {ok, #mcs_cjc{user = UserId, status = Result, channel = Channel}};

decode_dpdu(tokenInhibitRequest, #'TokenInhibitRequest'{initiator=UserId,
                                                        tokenId=Token}) ->
    {ok, #mcs_tir{user = UserId, token = Token}};

decode_dpdu(tokenInhibitConfirm, #'TokenInhibitConfirm'{initiator=UserId,
                                                        tokenId=Token,
                                                        result=Status,
                                                        tokenStatus=TokenStatus}) ->
    {ok, #mcs_tic{user = UserId, token = Token, status = Status,
                  token_status = TokenStatus}};

decode_dpdu(disconnectProviderUltimatum,
                        #'DisconnectProviderUltimatum'{reason=Reason}) ->
    {ok, #mcs_dpu{reason = Reason}};

decode_dpdu(Other, _) ->
    {error, {unhandled_mcsp_dpdu, Other}}.

decode_dpdu(Bin) ->
    case mcsp_per:decode('DomainMCSPDU', Bin) of
        {ok, {Type, Rec}, Rem} ->
            case Rem of
                <<0:(bit_size(Rem))>> -> decode_dpdu(Type, Rec);
                _ -> {error, {trailing_data, Type}}
            end;
        Err = {error, _} ->
            Err
    end.


encode_dpdu(#mcs_tic{user = UserId, token = Token, status = Status,
                     token_status = TokenStatus}) ->
    mcsp_per:encode('DomainMCSPDU', {tokenInhibitConfirm,
        #'TokenInhibitConfirm'{result = Status, tokenStatus = TokenStatus,
                               initiator = UserId, tokenId = Token}});

encode_dpdu(#mcs_auc{status = Result, user = UserId}) ->
    mcsp_per:encode('DomainMCSPDU', {attachUserConfirm,
        #'AttachUserConfirm'{result = Result, initiator = UserId}});

encode_dpdu(#mcs_cjc{channel = Channel, status = Result, user = UserId}) ->
    mcsp_per:encode('DomainMCSPDU', {channelJoinConfirm,
        #'ChannelJoinConfirm'{result = Result, initiator = UserId,
                              requested = Channel, channelId = Channel}});

encode_dpdu(#mcs_data{user = UserId, channel = Channel, priority = Priority,
                      data = Binary}) ->
    mcsp_per:encode('DomainMCSPDU', {sendDataRequest,
        #'SendDataRequest'{initiator = UserId, channelId = Channel,
                           dataPriority = Priority, segmentation = <<1:1, 1:1>>,
                           userData = Binary}});

encode_dpdu(#mcs_srv_data{user = UserId, channel = Channel,
                          priority = Priority, data = Binary}) ->
    mcsp_per:encode('DomainMCSPDU', {sendDataIndication,
        #'SendDataIndication'{initiator = UserId, channelId = Channel,
                              dataPriority = Priority, segmentation = <<1:1, 1:1>>,
                              userData = Binary}});

encode_dpdu(#mcs_dpu{reason = Reason}) ->
    mcsp_per:encode('DomainMCSPDU', {disconnectProviderUltimatum,
        #'DisconnectProviderUltimatum'{reason = Reason}});

encode_dpdu(_) -> {error, bad_dpdu}.

decode_ci(Bin) ->
    case mcsp_ber:decode('Connect-Initial', Bin) of
        {ok, CI, Rem} ->
            padding_only(Rem),
            Tgt = CI#'Connect-Initial'.targetParameters,
            Initial = #mcs_ci{calling = CI#'Connect-Initial'.callingDomainSelector,
                              called = CI#'Connect-Initial'.calledDomainSelector,
                              max_channels = Tgt#'DomainParameters'.maxChannelIds,
                              max_users = Tgt#'DomainParameters'.maxUserIds,
                              max_tokens = Tgt#'DomainParameters'.maxTokenIds,
                              num_priorities = Tgt#'DomainParameters'.numPriorities,
                              min_throughput = Tgt#'DomainParameters'.minThroughput,
                              max_height = Tgt#'DomainParameters'.maxHeight,
                              max_size = Tgt#'DomainParameters'.maxHeight,
                              version = Tgt#'DomainParameters'.protocolVersion},

            CDData = iolist_to_binary([CI#'Connect-Initial'.userData]),
            %lager:debug("cddata = ~p", [base64:encode(CDData)]),
            case gccp_per:decode('ConnectData', CDData) of
                {ok, CD, CDRem} ->
                    % Ok, so this is one of the greatest bugs in this whole sorry affair:
                    % The asn.1 generator in the official microsoft RDP client regularly
                    % generates the wrong length on the GCC ConnectData, but appends the full
                    % payload anyway. If this happens, you have to strip it off here and append
                    % it to the inner payload and *then* try to parse it again.
                    _ = if byte_size(CDRem) > 0 ->
                        lager:warning("ci connectdata is carrying ~B extra bytes", [byte_size(CDRem)]);
                    true -> ok end,

                    CPDUData = iolist_to_binary([CD#'ConnectData'.connectPDU]),
                    % Note we append the CDRem (if any) to the CPDUData here, see above
                    case gccp_per:decode('ConnectGCCPDU', <<CPDUData/binary, CDRem/binary>>) of
                        {ok, {conferenceCreateRequest, CCR}, <<>>} ->
                            #'ConferenceCreateRequest'{conferenceName = NameRec,
                                                       userData = UD} = CCR,
                            % Duca is a magic string
                            [#'UserData_SETOF'{key = {h221NonStandard, <<"Duca">>},
                                               value=ClientData}] = UD,
                            {ok, Initial#mcs_ci{
                                conf_name = NameRec#'ConferenceName'.numeric,
                                data = iolist_to_binary([ClientData])
                            }};
                        Other ->
                            %lager:debug("gccp_per failed: ~p", [Other]),
                            Other
                    end;
                Other ->
                    %lager:debug("gccp_per failed: ~p", [Other]),
                    Other
            end;
        Other ->
            %lager:debug("mcsp_ber failed: ~p", [Other]),
            Other
    end.

decode_cr(Bin) ->
    case mcsp_ber:decode('Connect-Response', Bin) of
        {ok, CR, Rem} ->
            padding_only(Rem),
            Tgt = CR#'Connect-Response'.domainParameters,
            Initial = #mcs_cr{called = CR#'Connect-Response'.calledConnectId,
                              mcs_result = CR#'Connect-Response'.result,
                              max_channels = Tgt#'DomainParameters'.maxChannelIds,
                              max_users = Tgt#'DomainParameters'.maxUserIds,
                              max_tokens = Tgt#'DomainParameters'.maxTokenIds,
                              num_priorities = Tgt#'DomainParameters'.numPriorities,
                              min_throughput = Tgt#'DomainParameters'.minThroughput,
                              max_height = Tgt#'DomainParameters'.maxHeight,
                              max_size = Tgt#'DomainParameters'.maxHeight,
                              version = Tgt#'DomainParameters'.protocolVersion},

            CDData = iolist_to_binary([CR#'Connect-Response'.userData]),
            case gccp_per:decode('ConnectData', CDData) of
                {ok, CD, CDRem} ->
                    % See above, Microsoft's ASN.1 generator can produce the wrong length here
                    _ = if byte_size(CDRem) > 0 ->
                        lager:warning("cr connectdata is carrying ~B extra bytes", [byte_size(CDRem)]);
                    true -> ok end,

                    CPDUData = iolist_to_binary([CD#'ConnectData'.connectPDU]),
                    % Note appending the CDRem here again
                    case gccp_per:decode('ConnectGCCPDU', <<CPDUData/binary,CDRem/binary>>) of
                        {ok, {conferenceCreateResponse, CCR}, <<>>} ->
                            #'ConferenceCreateResponse'{nodeID = Node,
                                                        tag = Tag,
                                                        result = Result,
                                                        userData = UD} = CCR,
                            % McDn is the magic string for a Connect-Response
                            [#'UserData_SETOF'{key = {h221NonStandard, <<"McDn">>},
                                               value=ClientData}] = UD,
                            CDataBin = iolist_to_binary([ClientData]),
                            {ok, Initial#mcs_cr{node = Node, tag = Tag,
                                                result = Result,
                                                data = CDataBin}};
                        Other ->
                            Other
                    end;
                Other ->
                    %lager:debug("gccp_per failed: ~p", [Other]),
                    Other
            end;
        Other ->
            Other
    end.

encode_cr(#mcs_cr{} = McsCr) ->
    UserData = #'UserData_SETOF'{key = {h221NonStandard, <<"McDn">>},
                                 value = (McsCr#mcs_cr.data)},
    CCR = #'ConferenceCreateResponse'{nodeID = McsCr#mcs_cr.node,
                                      tag = McsCr#mcs_cr.tag,
                                      result = McsCr#mcs_cr.result,
                                      userData = [UserData]},
    {ok, GccPdu} = gccp_per:encode('ConnectGCCPDU', {conferenceCreateResponse, CCR}),
    CD = #'ConnectData'{'t124Identifier' = {object, {0,0,20,124,0,1}},
                        connectPDU = (GccPdu)},
    {ok, CDData} = gccp_per:encode('ConnectData', CD),
    Params = #'DomainParameters'{maxChannelIds = McsCr#mcs_cr.max_channels,
                               maxUserIds = McsCr#mcs_cr.max_users,
                               maxTokenIds = McsCr#mcs_cr.max_tokens,
                               numPriorities = McsCr#mcs_cr.num_priorities,
                               minThroughput = McsCr#mcs_cr.min_throughput,
                               maxHeight = McsCr#mcs_cr.max_height,
                               maxMCSPDUsize = McsCr#mcs_cr.max_size,
                               protocolVersion = McsCr#mcs_cr.version},
    CR = #'Connect-Response'{calledConnectId = McsCr#mcs_cr.called,
                             result = McsCr#mcs_cr.mcs_result,
                             domainParameters = Params,
                             userData = (CDData)},
    {ok, CRData} = mcsp_ber:encode('Connect-Response', CR),

    {ok, CRData}.

encode_ci(#mcs_ci{} = McsCI) ->
    UserData = #'UserData_SETOF'{key = {h221NonStandard, <<"Duca">>},
                                 value = McsCI#mcs_ci.data},
    NameRec = #'ConferenceName'{numeric = McsCI#mcs_ci.conf_name},
    CCR = #'ConferenceCreateRequest'{conferenceName = NameRec,
                                     lockedConference = false,
                                     listedConference = false,
                                     conductibleConference = false,
                                     terminationMethod = automatic,
                                     userData = [UserData]},
    {ok, GccPdu} = gccp_per:encode('ConnectGCCPDU', {conferenceCreateRequest, CCR}),
    CD = #'ConnectData'{'t124Identifier' = {object, {0,0,20,124,0,1}},
                        connectPDU = (GccPdu)},
    {ok, CDData} = gccp_per:encode('ConnectData', CD),
    TargetParams = #'DomainParameters'{maxChannelIds = McsCI#mcs_ci.max_channels,
                                       maxUserIds = McsCI#mcs_ci.max_users,
                                       maxTokenIds = McsCI#mcs_ci.max_tokens,
                                       numPriorities = McsCI#mcs_ci.num_priorities,
                                       minThroughput = McsCI#mcs_ci.min_throughput,
                                       maxHeight = McsCI#mcs_ci.max_height,
                                       maxMCSPDUsize = McsCI#mcs_ci.max_size,
                                       protocolVersion = McsCI#mcs_ci.version},
    MinParams = #'DomainParameters'{maxChannelIds = 1, maxUserIds = 2, maxTokenIds = 1, numPriorities = 1, minThroughput = 0, maxHeight = 1, maxMCSPDUsize = 1024, protocolVersion = 2},
    MaxParams = #'DomainParameters'{maxChannelIds = 1024, maxUserIds = 1 bsl 20, maxTokenIds = 1024, numPriorities = 3, minThroughput = 1024, maxHeight = 1024, maxMCSPDUsize = 1 bsl 20, protocolVersion = 2},
    CI = #'Connect-Initial'{callingDomainSelector = McsCI#mcs_ci.calling,
                            calledDomainSelector = McsCI#mcs_ci.called,
                            upwardFlag = true,
                            targetParameters = TargetParams,
                            minimumParameters = MinParams,
                            maximumParameters = MaxParams,
                            userData = (CDData)},
    {ok, CIData} = mcsp_ber:encode('Connect-Initial', CI),

    {ok, CIData}.


-ifdef(TEST).

dec_hex_string([]) -> <<>>;
dec_hex_string([A | Rest]) when (A >= $0) and (A =< $9) ->
    <<(A - $0):4, (dec_hex_string(Rest))/bitstring>>;
dec_hex_string([A | Rest]) when (A >= $a) and (A =< $f) ->
    <<(A - $a + 10):4, (dec_hex_string(Rest))/bitstring>>;
dec_hex_string([A | Rest]) when (A == 32) or (A == 10) ->
    dec_hex_string(Rest).

spec_4_1_3_test() ->
    Pkt = dec_hex_string("7f 65 82 01 94 04 01 01 04 01 01 01 01 ff 30 19 02 01 22 02 01 02 02 01 00 02 01 01 02 01 00 02 01 01 02 02 ff ff 02 01 02 30 19 02 01 01 02 01 01 02 01 01 02 01 01 02 01 00 02 01 01 02 02 04 20 02 01 02 30 1c 02 02 ff ff 02 02 fc 17 02 02 ff ff 02 01 01 02 01 00 02 01 01 02 02 ff ff 02 01 02 04 82 01 33 00 05 00 14 7c 00 01 81 2a 00 08 00 10 00 01 c0 00 44 75 63 61 81 1c 01 c0 d8 00 04 00 08 00 00 05 00 04 01 ca 03 aa 09 04 00 00 ce 0e 00 00 45 00 4c 00 54 00 4f 00 4e 00 53 00 2d 00 44 00 45 00 56 00 32 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 ca 01 00 00 00 00 00 18 00 07 00 01 00 36 00 39 00 37 00 31 00 32 00 2d 00 37 00 38 00 33 00 2d 00 30 00 33 00 35 00 37 00 39 00 37 00 34 00 2d 00 34 00 32 00 37 00 31 00 34 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 04 c0 0c 00 0d 00 00 00 00 00 00 00 02 c0 0c 00 1b 00 00 00 00 00 00 00 03 c0 2c 00 03 00 00 00 72 64 70 64 72 00 00 00 00 00 80 80 63 6c 69 70 72 64 72 00 00 00 a0 c0 72 64 70 73 6e 64 00 00 00 00 00 c0"),
    ?assertMatch({ok, #mcs_ci{
        calling = [1], called = [1], max_channels = 34, max_users = 2,
        max_tokens = 0, num_priorities = 1, min_throughput = 0, max_height = 1,
        version = 2,
        data = <<16#01, 16#c0, _/binary>>
        }}, decode(Pkt)).

-endif.
