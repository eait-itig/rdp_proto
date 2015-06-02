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

-record(fp_pdu, {flags = [], signature, contents = []}).

-record(fp_inp_unknown, {type, remainder, flags}).
-record(fp_inp_scancode, {flags = [], action=down, code}).
-record(fp_inp_mouse, {action=move, buttons=[], point}).
-record(fp_inp_wheel, {point, clicks=0}).
-record(fp_inp_sync, {flags = []}).
-record(fp_inp_unicode, {code = 0, action = down}).

-record(fp_update_mouse, {mode = default :: default | hidden}).

-record(ts_surface_set_bits, {
	dest :: {X :: integer(), Y :: integer()},
	size :: {W :: integer(), H :: integer()},
	bpp = 24 :: integer(),
	codec :: integer(),
	data :: binary()
}).
-record(ts_surface_stream_bits, {
	dest :: {X :: integer(), Y :: integer()},
	size :: {W :: integer(), H :: integer()},
	bpp = 24 :: integer(),
	codec :: integer(),
	data :: binary()
}).
-record(ts_surface_frame_marker, {
	action :: start | finish,
	frame :: integer()
}).
-record(ts_update_surfaces, {
	surfaces = [] :: [#ts_surface_set_bits{} | #ts_surface_stream_bits{} | #ts_surface_frame_marker{}]
}).
