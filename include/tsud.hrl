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

-include_lib("rdp_proto/include/kbd.hrl").

-record(tsud_core, {version=[8,1], width, height, sas=16#aa03, kbd_layout=?KBDL_US, client_build=2600, client_name="localhost", kbd_type=?KBD_IBM101, kbd_sub_type=0, kbd_fun_keys=12, color='24bpp', colors=['24bpp'], capabilities=[errinfo], selected=[], conn_type=unknown}).

-record(tsud_svr_core, {version=[8,1], requested=[], capabilities=[]}).
-record(tsud_svr_net, {iochannel, channels=[]}).
-record(tsud_svr_security, {method=none, level=none, random="", certificate=""}).
-record(tsud_svr_msgchannel, {channel}).
-record(tsud_svr_multitransport, {flags=[]}).

-record(tsud_security, {methods=[]}).
-record(tsud_cluster, {flags=[], version=4, sessionid=none}).
-record(tsud_net, {channels=[]}).
-record(tsud_net_channel, {name=[], priority=low, flags=[]}).
-record(tsud_monitor, {flags=[], monitors=[]}).
-record(tsud_monitor_def, {left, top, right, bottom, flags=[]}).
-record(tsud_msgchannel, {flags = []}).
-record(tsud_monitor_ex, {flags = [], monitors=[]}).
-record(tsud_monitor_ex_attr, {phys_width, phys_height, angle, desktop_scale, device_scale}).
-record(tsud_multitransport, {flags = []}).

-record(tsud_unknown, {type, data}).

-type client_tsud() :: #tsud_core{} | #tsud_security{} | #tsud_cluster{} | #tsud_net{} | #tsud_monitor{} | #tsud_msgchannel{} | #tsud_monitor_ex{} | #tsud_multitransport{} | #tsud_unknown{}.
-type server_tsud() :: #tsud_svr_core{} | #tsud_svr_net{} | #tsud_svr_security{} | #tsud_svr_msgchannel{} | #tsud_svr_multitransport{}.
-type tsud() :: client_tsud() | server_tsud().
