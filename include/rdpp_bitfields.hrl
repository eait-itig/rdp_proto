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

-define(sec_flags, [flagshi_valid, heartbeat, autodetect_rsp, autodetect_req, salted_mac, redirection, encrypt_license, skip, license, info, ignore_seqno, reset_seqno, encrypt, multitrans_rsp, multitrans_req, security]).
-define(sec_types, [autodetect_rsp, autodetect_req, redirection, license, info, multitrans_rsp, multitrans_req, security, heartbeat]).

-define(cc_prot_flags, [{skip,28}, credssp_early, rdstls, credssp, ssl]).

-define(vchan_flags, [{skip,8}, mppc_flushed, mppc_at_front, compression, skip, {compress_type, 4}, {skip,9}, resume, suspend, show_protocol, {skip, 2}, last, first]).

-define(ts_cap_general_flags, [{skip, 5}, short_bitmap_hdr, {skip, 5}, salted_mac, autoreconnect, long_creds, skip, fastpath, refresh_rect, suppress_output]).

-define(ts_cap_order_flags, [{skip,8}, extra, solid_pattern_brush_only, colorindex, skip, zeroboundsdeltas, skip, negotiate, skip]).
-define(ts_cap_orders, [
        {dstblt,8}, {patblt,8}, {scrblt,8}, {memblt,8}, {mem3blt,8}, {skip,16}, {drawninegrid,8},
        {lineto,8}, {multidrawninegrid,8}, {skip,8}, {savebitmap,8}, {skip,24}, {multidstblt,8},
        {multipatblt,8}, {multiscrblt,8}, {multiopaquerect,8}, {fastindex,8}, {polygonsc,8},
        {polygoncb,8}, {polyline,8}, {skip,8}, {fastglyph,8}, {ellipsesc,8}, {ellipsecb,8},
        {index,8}, {skip,32}
    ]).

-define(ts_cap_input_flags, [{skip, 10}, fastpath2, unicode, fastpath, mousex, skip, scancodes]).

-define(ts_cap_bitmap_flags, [{skip,4}, skip_alpha, subsampling, dynamic_bpp, skip, resize, compression, multirect]).

-define(ts_cap_surface_flags, [{skip,25},streamsurfacebits,skip,framemarker,{skip,2},setsurfacebits,skip]).

-define(ts_inpevt_sync_flags, [{skip,12}, kanalock, capslock, numlock, scrolllock]).

-define(ts_info_perf_flags, [{skip,23}, composition, font_smoothing, no_cursor_settings, no_cursor_shadow, skip, no_themes, no_menu_anim, no_full_win_drag, no_wallpaper]).
-define(ts_info_flags, [
                {skip,6}, rail_hd, {skip,2}, no_video, audio_in, saved_creds, no_audio, smartcard_pin,
                mouse_wheel, logon_errors, rail, force_encrypt, remote_console_audio, {skip,4},
                windows_key, compression, logon_notify, maximize_shell, unicode, autologon, skip,
                disable_salute, mouse
            ]).
