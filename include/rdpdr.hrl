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

-record(rdpdr_srv_announce, {
	version = {1,13} :: {integer(), integer()},
	clientid = 0 :: integer()
	}).
-record(rdpdr_clientid_confirm, {
	version = {1,13} :: {integer(), integer()},
	clientid = 0 :: integer()
	}).
-record(rdpdr_client_name_req, {
	unicode = false :: boolean(),
	name = "" :: string()
	}).
-record(rdpdr_server_caps, {
	caps = [] :: [rdpdr:cap()]
	}).
-record(rdpdr_client_caps, {
	caps = [] :: [rdpdr:cap()]
	}).
-record(rdpdr_device_announce, {
	devices = [] :: [rdpdr:dev()]
	}).
-record(rdpdr_device_reply, {
	id :: rdpdr:dev_id(),
	status :: msrpce:ntstatus()
	}).
-record(rdpdr_device_remove, {
	device_ids = [] :: [rdpdr:dev_id()]
	}).

-record(rdpdr_cap_general, {
	os_type = 0 :: integer(),
	os_version = 0 :: integer(),
	version = {1,13} :: {integer(), integer()},
	ioreqs = [create, cleanup, close, read, write, flush_buffers, shutdown,
		  device_control, query_volume_info, set_volume_info,
		  query_info, set_info, dir_control, lock_control] :: rdpdr:io_reqs(),
	pdus = [client_name] :: rdpdr:extpdu(),
	flags = [] :: rdpdr:cap_flags(),
	specials = none
	}).
-record(rdpdr_cap_printer, {}).
-record(rdpdr_cap_port, {}).
-record(rdpdr_cap_drive, {}).
-record(rdpdr_cap_smartcard, {}).

-record(rdpdr_dev_serial, {
	id :: rdpdr:dev_id(),
	dos_name :: rdpdr:dos_name()
	}).
-record(rdpdr_dev_parallel, {
	id :: rdpdr:dev_id(),
	dos_name :: rdpdr:dos_name()
	}).
-record(rdpdr_dev_printer, {
	id :: rdpdr:dev_id(),
	dos_name :: rdpdr:dos_name()
	}).
-record(rdpdr_dev_fs, {
	id :: rdpdr:dev_id(),
	dos_name :: rdpdr:dos_name(),
	name :: string()
	}).
-record(rdpdr_dev_smartcard, {
	id :: rdpdr:dev_id(),
	dos_name :: rdpdr:dos_name()
	}).

-record(rdpdr_io, {
	device_id :: rdpdr:dev_id(),
	req_id :: rdpdr:req_id(),
	file_id = 0 :: rdpdr:file_id()
	}).

-record(rdpdr_io_resp, {
	io :: #rdpdr_io{},
	status :: undefined | msrpce:ntstatus(),
	data :: binary()
	}).

-record(rdpdr_open_req, {
	io :: #rdpdr_io{},
	access :: rdpdr:access_mode(),
	alloc_size :: integer(),
	attrs :: rdpdr:file_attrs(),
	share :: rdpdr:share_mode(),
	dispos :: rdpdr:create_dispos(),
	flags :: rdpdr:create_flags(),
	path :: string()
	}).

-record(rdpdr_open_resp, {
	io :: #rdpdr_io{},
	file_id :: rdpdr:file_id(),
	status :: ok | superseded | opened | overwritten
	}).

-record(rdpdr_close_req, {
	io :: #rdpdr_io{}
	}).

-record(rdpdr_close_resp, {
	io :: #rdpdr_io{}
	}).

-record(rdpdr_control_req, {
	io :: #rdpdr_io{},
	code :: integer(),
	expect_len :: integer(),
	data :: binary()
	}).

-record(rdpdr_control_resp, {
	io :: #rdpdr_io{},
	data :: binary()
	}).
