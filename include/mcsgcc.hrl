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

-ifndef(MCSGCC_HRL).
-define(MCSGCC_HRL, 1).

-type mcs_user() :: none | integer().
-type mcs_chan() :: none | integer().

-record(mcs_ci, {data, calling=[1], called=[1], max_channels=34, max_users=2, max_tokens=0, num_priorities=1, min_throughput=0, max_height=1, max_size=65535, version=2, conf_name=""}).

-record(mcs_cr, {data, called=0, max_channels=34, max_users=2, max_tokens=0, num_priorities=1, min_throughput=0, max_height=1, max_size=65535, version=2, mcs_result = 'rt-successful', node=1001, tag=1, result=success}).

-record(mcs_edr, {height=0, interval=0}).
-record(mcs_aur, {}).
-record(mcs_auc, {status='rt-successful', user}).
-record(mcs_cjr, {channel, user}).
-record(mcs_cjc, {channel, status='rt-successful', user}).
-record(mcs_tir, {user, token}).
-record(mcs_tic, {user, token, status='rt-successful', token_status='notInUse'}).
-record(mcs_data, {user, channel, priority=high, data}).
-record(mcs_srv_data, {user, channel, priority=high, data}).
-record(mcs_dpu, {reason='rn-user-requested'}).

-endif.
