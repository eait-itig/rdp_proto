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

-module(rdp_server_sup).

-behaviour(supervisor).
-export([start_link/2, init/1, start_frontend/1]).
-export([initial_listeners/1]).

-spec start_link(Port :: integer(), Mod :: atom() | {atom(), term()}) -> {ok, pid()} | {error, term()}.
start_link(Port, {Mod, ModInitArg}) ->
    supervisor:start_link(?MODULE, [Port, {Mod, [ModInitArg]}]);
start_link(Port, Mod) ->
    supervisor:start_link(?MODULE, [Port, Mod]).

start_frontend(Sup) ->
    supervisor:start_child(Sup, []).

%% @private
initial_listeners(Sup) ->
    [start_frontend(Sup) || _ <- lists:seq(1,20)],
    ok.

init([Port, ModArg]) ->
    {ok, ListenSocket} = gen_tcp:listen(Port, [binary, {active, false}, {keepalive, true}, {reuseaddr, true}]),
    spawn_link(?MODULE, initial_listeners, [self()]),
    Server = {undefined,
        {rdp_server_fsm, start_link, [ListenSocket, ModArg, self()]},
        temporary, 1000, worker, [rdp_server_fsm]},
    {ok, {{simple_one_for_one, 60, 60}, [Server]}}.
