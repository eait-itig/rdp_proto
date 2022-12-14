%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>
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

-module(cliprdr_fsm).

-compile([{parse_transform, lager_transform}]).

-behaviour(gen_statem).
-behaviour(rdp_vchan_fsm).

-include("rdpp.hrl").
-include("mcsgcc.hrl").
-include("cliprdr.hrl").

-export([list_formats/1, paste/2, copy/2]).
-export([start_link/2, handle_pdu/2]).
-export([startup/3, copied/3, local_copied/3]).
-export([init/1, terminate/3, callback_mode/0]).

-spec start_link(rdp_server:server(), mcs_chan()) -> {ok, pid()} | {error, term()}.
start_link(Srv, VChanId) ->
    gen_statem:start_link(?MODULE, [Srv, VChanId], []).

-spec handle_pdu(pid(), #ts_vchan{}) -> ok | {error, term()}.
handle_pdu(Pid, VPdu) ->
    gen_statem:cast(Pid, {vpdu, VPdu}).

-spec list_formats(pid()) -> {ok, [cliprdr:format()]} | {error, term()}.
list_formats(Pid) ->
    gen_statem:call(Pid, list_formats).

-spec paste(pid(), cliprdr:format()) -> {ok, term()} | {error, term()}.
paste(Pid, Format) ->
    gen_statem:call(Pid, {paste, Format}).

-spec copy(pid(), #{cliprdr:format() => iolist()}) -> ok | {error, term()}.
copy(Pid, FormatMap) ->
    gen_statem:call(Pid, {copy, FormatMap}).

-record(?MODULE, {
    srv :: rdp_server:server(),
    chanid :: integer(),
    formats = [] :: [cliprdr:format()],
    caps = [] :: [cliprdr:cliprdr_cap()],
    pasteq = queue:new() :: queue:queue(pid()),
    data = #{} :: #{cliprdr:format() => iolist()}
    }).

callback_mode() -> [state_functions, state_enter].

init([Srv, ChanId]) ->
    {ok, startup, #?MODULE{srv = Srv, chanid = ChanId}}.

terminate(_Reason, _State, #?MODULE{}) ->
    ok.

startup(enter, _PrevState, #?MODULE{srv = Srv, chanid = ChanId}) ->
    CapsData = cliprdr:encode(#cliprdr_caps{
        flags = [first, last, show_protocol],
        caps = [#cliprdr_cap_general{flags = [files, locking, long_names]}]
    }),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = CapsData
    }),
    MonReadyData = cliprdr:encode(#cliprdr_monitor_ready{}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = MonReadyData
    }),
    keep_state_and_data;

startup(cast, {pdu, Pdu = #cliprdr_caps{caps = Caps}}, S0 = #?MODULE{srv = Srv}) ->
    S1 = S0#?MODULE{caps = Caps},
    {Pid, _} = Srv,
    _ = lager:debug("cliprdr caps for ~p: ~s", [Pid, cliprdr:pretty_print(Pdu)]),
    {keep_state, S1};

startup(cast, {pdu, #cliprdr_format_list{formats = Fmts}}, S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    S1 = S0#?MODULE{formats = Fmts},
    FmtRespData = cliprdr:encode(#cliprdr_format_resp{flags = [ok]}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = FmtRespData
    }),
    {next_state, copied, S1};

startup({call, From}, list_formats, #?MODULE{}) ->
    gen_statem:reply(From, {error, starting_up}),
    keep_state_and_data;

startup({call, From}, {paste, _}, #?MODULE{}) ->
    gen_statem:reply(From, {error, starting_up}),
    keep_state_and_data;

startup({call, From}, {copy, Map}, S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    Formats = maps:keys(Map),
    FmtListData = cliprdr:encode(#cliprdr_format_list{formats = Formats}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = FmtListData
    }),
    S1 = S0#?MODULE{data = Map, formats = Formats},
    {next_state, local_copied, S1};

startup(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    decode_vpdu(VPdu, S0).

copied(enter, _PrevState, #?MODULE{}) ->
    keep_state_and_data;

copied(cast, {pdu, #cliprdr_format_list{formats = Fmts}}, S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    S1 = S0#?MODULE{formats = Fmts},
    FmtRespData = cliprdr:encode(#cliprdr_format_resp{flags = [ok]}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = FmtRespData
    }),
    {keep_state, S1};

copied({call, From}, list_formats, #?MODULE{formats = Fmts}) ->
    gen_statem:reply(From, {ok, Fmts}),
    keep_state_and_data;

copied({call, From}, {paste, Format}, S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    #?MODULE{pasteq = Q0, formats = Fmts} = S0,
    Q1 = queue:in({From, Format}, Q0),
    S1 = S0#?MODULE{pasteq = Q1},
    FmtId = case lists:keyfind(Format, 2, Fmts) of
        false when is_atom(Format) or is_integer(Format) -> Format;
        {Id, _Name} -> Id
    end,
    DataReqData = cliprdr:encode(#cliprdr_data_req{format = FmtId}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = DataReqData
    }),
    {keep_state, S1};

copied(cast, {pdu, #cliprdr_data_resp{flags = Flags, data = Data0}}, S0 = #?MODULE{}) ->
    #?MODULE{pasteq = Q0} = S0,
    {{value, {From, Format}}, Q1} = queue:out(Q0),
    S1 = S0#?MODULE{pasteq = Q1},
    case lists:member(ok, Flags) of
        false ->
            _ = lager:debug("cliprdr flags = ~p", [Flags]),
            gen_statem:reply(From, {error, paste_failed}),
            {keep_state, S1};
        true ->
            Data1 = case Format of
                unicode ->
                    WithZero = unicode:characters_to_binary(Data0,
                        {utf16, little}, utf8),
                    [WithoutZero | _] = binary:split(WithZero, <<0>>),
                    WithoutZero;
                _ ->
                    Data0
            end,
            gen_statem:reply(From, {ok, Data1}),
            {keep_state, S1}
    end;

copied({call, From}, {copy, Map}, S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    Formats = maps:keys(Map),
    FmtListData = cliprdr:encode(#cliprdr_format_list{formats = Formats}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = FmtListData
    }),
    S1 = S0#?MODULE{data = Map, formats = Formats},
    {next_state, local_copied, S1};

copied(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    decode_vpdu(VPdu, S0).

local_copied(enter, _PrevState, #?MODULE{}) ->
    keep_state_and_data;

local_copied(cast, {pdu, #cliprdr_format_list{}}, S0 = #?MODULE{}) ->
    {next_state, copied, S0, [postpone]};

local_copied({call, From}, list_formats, #?MODULE{formats = Fmts}) ->
    gen_statem:reply(From, {ok, Fmts}),
    keep_state_and_data;

local_copied({call, From}, {paste, Format}, S0 = #?MODULE{data = Map}) ->
    case Map of
        #{Format := Data} ->
            gen_statem:reply(From, {ok, Data});
        _ ->
            gen_statem:reply(From, {error, bad_format})
    end,
    keep_state_and_data;

local_copied(cast, {pdu, #cliprdr_format_resp{}}, S0 = #?MODULE{}) ->
    keep_state_and_data;

local_copied(cast, {pdu, #cliprdr_data_req{format = Fmt}}, S0 = #?MODULE{srv = Srv, chanid = ChanId, data = Map}) ->
    Data = case Map of
        #{Fmt := D} ->
            iolist_to_binary(D);
        #{text := D} ->
            iolist_to_binary(D);
        _ ->
            <<>>
    end,
    DataRespData = cliprdr:encode(#cliprdr_data_resp{data = Data}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = DataRespData
    }),
    keep_state_and_data;

local_copied({call, From}, {copy, Map}, S0 = #?MODULE{srv = Srv, chanid = ChanId}) ->
    Formats = maps:keys(Map),
    FmtListData = cliprdr:encode(#cliprdr_format_list{formats = Formats}),
    ok = rdp_server:send_vchan(Srv, ChanId, #ts_vchan{
        flags = [first, last, show_protocol],
        data = FmtListData
    }),
    S1 = S0#?MODULE{data = Map, formats = Formats},
    {next_state, local_copied, S1};

local_copied(cast, {vpdu, VPdu}, S0 = #?MODULE{}) ->
    decode_vpdu(VPdu, S0).


decode_vpdu(VPdu = #ts_vchan{flags = _Fl, data = D}, #?MODULE{caps = Caps}) ->
    case cliprdr:decode(D, Caps) of
        {ok, ClipPdu} ->
            %lager:debug("cliprdr: ~s", [cliprdr:pretty_print(ClipPdu)]),
            {keep_state_and_data, [{next_event, cast, {pdu, ClipPdu}}]};
        Err ->
            lager:debug("cliprdr decode fail: ~p (~s)", [Err, rdpp:pretty_print(VPdu)]),
            keep_state_and_data
    end.
