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

-module(mppc_nif).

-export([
    new_context/1,
    set_level/2,
    get_level/1,
    compress/2,
    decompress/3,
    reset/2
    ]).
-on_load(init/0).

-export_type([context/0]).

try_paths([Last], BaseName) ->
    filename:join([Last, BaseName]);
try_paths([Path | Next], BaseName) ->
    case filelib:is_dir(Path) of
        true ->
            WCard = filename:join([Path, "{lib,}" ++ BaseName ++ ".*"]),
            case filelib:wildcard(WCard) of
                [] -> try_paths(Next, BaseName);
                _ -> filename:join([Path, BaseName])
            end;
        false -> try_paths(Next, BaseName)
    end.

init() ->
    Paths0 = [
        filename:join(["..", lib, rdp_proto, priv]),
        filename:join(["..", priv]),
        filename:join([priv])
    ],
    Paths1 = case code:priv_dir(rdp_proto) of
        {error, bad_name} -> Paths0;
        Dir -> [Dir | Paths0]
    end,
    SoName = try_paths(Paths1, "mppc_nif"),
    erlang:load_nif(SoName, 0).

-opaque context() :: reference().
-type level() :: '8k' | '64k'.
-type flags() :: [compressed | at_front | flushed].
-type mode() :: compress | decompress.

-spec new_context(mode()) -> {ok, context()}.
new_context(_Mode) -> error(no_nif).

-spec set_level(context(), level()) -> ok.
set_level(_Context, _Level) -> error(no_nif).

-spec get_level(context()) -> level().
get_level(_Context) -> error(no_nif).

-spec reset(context(), boolean()) -> ok.
reset(_Context, _Flush) -> error(no_nif).

-spec compress(context(), iolist()) -> {ok, iolist(), flags()}.
compress(_Context, _Data) -> error(no_nif).

-spec decompress(context(), iolist(), flags()) -> {ok, iolist()}.
decompress(_Context, _Data, _Flags) -> error(no_nif).

