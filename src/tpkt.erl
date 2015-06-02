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

-module(tpkt).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([encode/1, decode/1]).

-spec encode(Binary :: binary()) -> {ok, binary()}.
encode(Binary) ->
    Sz = byte_size(Binary) + 4,
    {ok, <<3, 0, Sz:16/big, Binary/binary>>}.

-spec decode(Binary :: binary()) -> {ok, Body :: binary()} | {error, term()}.
decode(Binary) ->
    case Binary of
        <<3, 0, Length:16/big, Rest/binary>> ->
            RealLength = Length - 4,
            RemLength = byte_size(Rest),
            if RealLength =< RemLength ->
                <<Body:RealLength/binary, Rem/binary>> = Rest,
                {ok, Body, Rem};
            true ->
                {error, bad_length}
            end;
        _ ->
            {error, bad_tpkt}
    end.

-ifdef(TEST).

-endif.
