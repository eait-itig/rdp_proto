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

-module(rdpserv_example).
-behaviour(rdp_server).

-compile([{parse_transform, lager_transform}]).

-include("rdp_server.hrl").
-include("rdpdr.hrl").

-export([
    init/1,
    handle_connect/4,
    init_ui/2,
    handle_event/3,
    terminate/2,
    choose_format/3,
    handle_info/3
    ]).

-record(state, {}).

%% @arg Peer  the peer address (IPv4 or IPv6) connecting
init(_Peer) ->
    {ok, #state{}}.

handle_connect(Cookie, Protocols, Srv, S = #state{}) ->
    {accept, [{certfile, "etc/cert.pem"}, {keyfile, "etc/key.pem"}], S}.
    % SslOptions should probably contain at least [{certfile, ...}, {keyfile, ...}]

choose_format(Preferred, Supported, S = #state{}) ->
    lager:debug("using color format ~p out of ~p", [Preferred, Supported]),
    {Preferred, S}.

init_ui(Srv, S = #state{}) ->
    % draw your initial ui here, eg:
    {W, H, Bpp} = rdp_server:get_canvas(Srv),
    ok = rdp_server:send_update(Srv, #ts_update_orders{orders = [
            #ts_order_opaquerect{
                dest = {round(W/2 - 50), round(H/2 - 50)},
                size = {100,100},
                bpp = Bpp,
                color = {100, 0, 0}  % red,green,blue 0-255
            }
        ]}),
    {ok, S}.

handle_event(#ts_inpevt_mouse{point = {X,Y}, action=move}, Srv, S = #state{}) ->
    % handle a mouse movement event, react by redrawing part of your ui
    % etc etc
    {ok, S};

handle_event(#ts_inpevt_mouse{action = down}, Srv, S = #state{}) ->
    {ok, D} = rdp_server:get_vchan_pid(Srv, cliprdr_fsm),
    spawn_link(fun () ->
        Res = cliprdr_fsm:copy(D, #{
            text => "hello",
            unicode => unicode:characters_to_binary("hello", utf8, {utf16,little})
        }),
        lager:debug("cliprdr copy = ~p", [Res])
    end),
    {ok, S};

handle_event(#ts_inpevt_mouse{}, Srv, S = #state{}) ->
    {ok, S};

handle_event(#ts_inpevt_key{}, Srv, S = #state{}) ->
    {ok, S};

handle_event(#ts_inpevt_sync{}, Srv, S = #state{}) ->
    {ok, S}.

handle_info(Msg, Srv, S = #state{}) ->
    lager:debug("got example msg: ~p", [Msg]),
    {ok, S}.

terminate(_Reason, #state{}) ->
    % any cleanup you need to do at exit
    ok.
