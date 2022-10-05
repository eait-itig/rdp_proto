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
    terminate/2
    ]).

-record(state, {}).

%% @arg Peer  the peer address (IPv4 or IPv6) connecting
init(_Peer) ->
    {ok, #state{}}.

handle_connect(Cookie, Protocols, Srv, S = #state{}) ->
    {accept, [{certfile, "etc/cert.pem"}, {keyfile, "etc/key.pem"}], S}.
    % SslOptions should probably contain at least [{certfile, ...}, {keyfile, ...}]

init_ui(Srv, S = #state{}) ->
    % draw your initial ui here, eg:
    ok = rdp_server:send_update(Srv, #ts_update_orders{orders = [
            #ts_order_opaquerect{
                dest = {0,0}, size = {100,100},
                color = {100, 0, 0}  % red,green,blue 0-255
            }
        ]}),
    {ok, S}.

handle_event(#ts_inpevt_mouse{point = {X,Y}, action=move}, Srv, S = #state{}) ->
    % handle a mouse movement event, react by redrawing part of your ui
    % etc etc
    {ok, S};

handle_event(#ts_inpevt_mouse{action = down}, Srv, S = #state{}) ->
    {ok, D} = rdp_server:get_vchan_pid(Srv, rdpdr_fsm),
    spawn_link(fun () ->
        {ok, [#rdpdr_dev_smartcard{id = DevId}]} = rdpdr_fsm:get_devices(D),

        {ok, SC0} = rdpdr_scard:open(D, DevId, system),
        {ok, Groups, SC1} = rdpdr_scard:list_groups(SC0),
        [Group0 | _] = Groups,
        {ok, Readers, SC2} = rdpdr_scard:list_readers(Group0, SC1),
        [Reader | _] = Readers,
        lager:debug("first reader is ~s", [Reader]),
        {ok, Mode, SC3} = rdpdr_scard:connect(Reader, shared, {t0_or_t1, optimal}, SC2),
        lager:debug("connected to ~p: ~p", [Reader, Mode]),
        {ok, SC4} = rdpdr_scard:begin_txn(SC3),
        {ok, Response, SC5} = rdpdr_scard:transceive(<<0,164,4,0,9,160,0,0,3,8,0,0,16,0>>, SC4),
        lager:debug("response = ~p", [Response]),
        {ok, SC6} = rdpdr_scard:end_txn(leave, SC5),
        {ok, SC7} = rdpdr_scard:disconnect(leave, SC6),
        ok = rdpdr_scard:close(SC7)
    end),
    {ok, S};

handle_event(#ts_inpevt_mouse{}, Srv, S = #state{}) ->
    {ok, S};

handle_event(#ts_inpevt_key{}, Srv, S = #state{}) ->
    {ok, S};

handle_event(#ts_inpevt_sync{}, Srv, S = #state{}) ->
    {ok, S}.

terminate(_Reason, #state{}) ->
    % any cleanup you need to do at exit
    ok.