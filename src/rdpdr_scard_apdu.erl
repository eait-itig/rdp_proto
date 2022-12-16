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

-module(rdpdr_scard_apdu).

-behaviour(apdu_transform).

-export([
    formats/0,
    init/2,
    begin_transaction/1,
    command/2,
    reply/2,
    end_transaction/2,
    terminate/1
    ]).

formats() -> {binary, undefined}.

-record(?MODULE, {
    scard :: rdpdr_scard:state()
    }).

init(_, [SCard]) ->
    {ok, #?MODULE{scard = SCard}}.

terminate(#?MODULE{}) -> ok.

begin_transaction(S0 = #?MODULE{scard = SC0}) ->
    case rdpdr_scard:begin_txn(SC0) of
        {ok, SC1} ->
            {ok, S0#?MODULE{scard = SC1}};
        {error, {scard, reset_card}} ->
            case rdpdr_scard:reconnect(reset, SC0) of
                {ok, _Mode, SC1} ->
                    begin_transaction(S0#?MODULE{scard = SC1});
                Err ->
                    Err
            end;
        {error, {scard, unpowered_card}} ->
            case rdpdr_scard:reconnect(unpower, SC0) of
                {ok, _Mode, SC1} ->
                    begin_transaction(S0#?MODULE{scard = SC1});
                Err ->
                    Err
            end;
        Err ->
            Err
    end.

end_transaction(Dispos, S0 = #?MODULE{scard = SC0}) ->
    case rdpdr_scard:end_txn(Dispos, SC0) of
        {ok, SC1} ->
            {ok, Dispos, S0#?MODULE{scard = SC1}};
        Err ->
            Err
    end.

command({Proto, Data}, S0 = #?MODULE{scard = SC0}) ->
    case rdpdr_scard:transceive(Data, SC0) of
        {ok, RespData, SC1} ->
            {ok, [{Proto, RespData}], [], S0#?MODULE{scard = SC1}};
        {error, {scard, reset_card}} ->
            case rdpdr_scard:reconnect(reset, SC0) of
                {ok, _Mode, SC1} ->
                    command({Proto, Data}, S0#?MODULE{scard = SC1});
                Err ->
                    Err
            end;
        {error, {scard, unpowered_card}} ->
            case rdpdr_scard:reconnect(unpower, SC0) of
                {ok, _Mode, SC1} ->
                    command({Proto, Data}, S0#?MODULE{scard = SC1});
                Err ->
                    Err
            end;
        Err ->
            Err
    end.

reply(_, #?MODULE{}) -> {error, sink_module}.
