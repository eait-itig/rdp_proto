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

-include_lib("rdp_proto/include/x224.hrl").
-include_lib("rdp_proto/include/mcsgcc.hrl").
-include_lib("rdp_proto/include/kbd.hrl").
-include_lib("rdp_proto/include/tsud.hrl").
-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/fastpath.hrl").
-include_lib("rdp_proto/include/cliprdr.hrl").

-type net_channel() :: #tsud_net_channel{}.

-record(x224_state, {
    us = none :: x224_ref(),
    them = none :: x224_ref()
    }).

-record(mcs_state, {
    us = none :: mcs_user(),
    them = none :: mcs_user(),
    iochan = none :: mcs_chan(),
    msgchan = none :: mcs_chan(),
    chans = [] :: [{mcs_chan(), net_channel()}]
    }).
