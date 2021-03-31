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
-include_lib("rdp_proto/include/mcsgcc.hrl").

-define(ROP_BLACKNESS, 16#00).
-define(ROP_SRCCOPY, 16#CC).
-define(ROP_SRCPAINT, 16#EE).
-define(ROP_PATCOPY, 16#F0).
-define(ROP_WHITENESS, 16#FF).
-define(ROP_SRCAND, 16#88).
-define(ROP_SRCINVERT, 16#66).

-define(GUID_NSCODEC, <<16#ca8d1bb9:32/little, 16#000f:16/little, 16#154f:16/little, 16#58, 16#9f, 16#ae, 16#2d, 16#1a, 16#87, 16#e2, 16#d6>>).
-define(GUID_REMOTEFX, <<16#76772F12:32/little, 16#BD72:16/little, 16#4463:16/little, 16#AF, 16#B3, 16#B7, 16#3C, 16#9C, 16#6F, 16#78, 16#86>>).
-define(GUID_REMOTEFX_IMAGE, <<16#2744CCD4:32/little, 16#9D8A:16/little, 16#4E74:16/little, 16#80, 16#3C, 16#0E, 16#CB, 16#EE, 16#A1, 16#9C, 16#54>>).
-define(GUID_JPEG, <<16#430C9EED:32/little, 16#1BAF:16/little, 16#4CE6:16/little, 16#86, 16#9A, 16#CB, 16#8B, 16#37, 16#B6, 16#62, 16#37>>).
-define(GUID_IGNORE, <<16#9C4351A6:32/little, 16#3535:16/little, 16#42AE:16/little, 16#91, 16#0C, 16#CD, 16#FC, 16#E5, 16#76, 16#0B, 16#58>>).

-record(ts_vchan, {flags = [], data}).

-record(ts_security, {secflags = [], random=[]}).
-record(ts_info, {secflags = [], codepage=0, flags = [mouse, noaudio], compression='8k', domain="", username="", password="", shell="", workdir="", client_address, client_dir, session_id, perf_flags, reconnect_cookie, dynamic_dst, extra, timezone}).
-record(ts_timezone, {bias, name, dst_name, dst_bias, dst_start, dst_end}).
-record(ts_license_vc, {secflags = []}).
-record(ts_heartbeat, {secflags = [], period=30, warning=3, reconnect=5}).

-record(ts_cap_general, {os=[unix, native_x11], flags=[suppress_output, refresh_rect, short_bitmap_hdr, autoreconnect, long_creds, salted_mac]}).
-record(ts_cap_bitmap, {bpp, flags=[compression, multirect, resize], width=1024, height=768}).
-record(ts_cap_share, {channel :: mcs_chan()}).
-record(ts_cap_order, {flags=[negotiate, zeroboundsdeltas], orders=[dstblt,patblt,scrblt,memblt,mem3blt,lineto,savebitmap,multidstblt,multipatblt,multiscrblt,multiopaquerect,fastindex,polygonsc,polygoncb,polyline,fastglyph,ellipsesc,ellipsecb,index]}).
-record(ts_cap_input, {flags=[mousex, scancodes, unicode], kbd_layout=?KBDL_US, kbd_type=?KBD_IBM101, kbd_sub_type=0, kbd_fun_keys=12, ime=""}).
-record(ts_cap_surface, {flags=[setsurfacebits, streamsurfacebits, framemarker]}).
-record(ts_cap_font, {flags=[fontlist]}).
-record(ts_cap_pointer, {flags=[color], cache_size=25}).
-record(ts_cap_vchannel, {flags=[], chunksize=1600}).
-record(ts_cap_control, {flags=[], control=never, detach=never}).
-record(ts_cap_activation, {helpkey=0, wmkey=0, helpexkey=0}).
-record(ts_cap_multifrag, {maxsize=64*1024}).
-record(ts_cap_gdip, {flags=[supported,cache], version=0, cache_entries=[], cache_sizes=[], image_cache=[]}).
-record(ts_cap_bitmapcache, {flags=[rev2, persistent_keys, waiting_list], cells=[]}).
-record(ts_cap_bitmapcache_cell, {count, size, flags=[]}).
-record(ts_cap_brush, {flags=[color_8x8, color_full]}).
-record(ts_cap_large_pointer, {flags=[support_96x96]}).
-record(ts_cap_bitmap_codecs, {codecs = []}).
-record(ts_cap_bitmap_codec, {codec, guid, id, properties=[]}).
-record(ts_cap_colortable, {cache_size = 6}).

-type ts_cap() :: #ts_cap_general{} | #ts_cap_bitmap{} | #ts_cap_share{} | #ts_cap_order{} | #ts_cap_input{} | #ts_cap_surface{} | #ts_cap_font{} | #ts_cap_pointer{} | #ts_cap_vchannel{} | #ts_cap_control{} | #ts_cap_activation{} | #ts_cap_multifrag{} | #ts_cap_gdip{} | #ts_cap_bitmapcache{} | #ts_cap_brush{} | #ts_cap_large_pointer{} | #ts_cap_bitmap_codecs{} | #ts_cap_colortable{}.

-record(ts_demand, {channel, shareid, sourcedesc=[], capabilities=[] :: [ts_cap()]}).
-record(ts_confirm, {channel, shareid, sourcedesc=[], capabilities=[] :: [ts_cap()]}).
-record(ts_deactivate, {channel, shareid, sourcedesc=[]}).
-record(ts_redir, {channel, shareid, sessionid, username=[], domain=[], password=[], cookie=[], flags=[logon], address, fqdn}).

-record(ts_sharedata, {channel, priority=high, comptype=none, flags=[], shareid, data={}}).
-record(ts_sync, {user}).
-record(ts_shutdown, {}).
-record(ts_shutdown_denied, {}).
-record(ts_control, {action, grantid, controlid}).
-record(ts_fontlist, {}).
-record(ts_fontmap, {}).
-record(ts_monitor_layout, {monitors=[]}).

-record(ts_order_opaquerect, {flags=[], dest, size, color={0,0,0}, bpp = 24}).
-record(ts_order_srcblt, {flags=[], dest, src, size, rop = ?ROP_SRCCOPY}).
-record(ts_order_line, {flags=[], start, finish, rop=?ROP_PATCOPY, color={0,0,0}, bpp = 24}).
-record(ts_update_orders, {orders=[]}).

-record(ts_bitmap_comp_info, {flags=[], scan_width, full_size}).
-record(ts_bitmap, {dest, size, bpp=24, comp_info = #ts_bitmap_comp_info{}, data}).
-record(ts_update_bitmaps, {bitmaps=[]}).

-record(ts_inpevt_sync, {flags=[]}).
-record(ts_inpevt_key, {code=0, action=down, flags=[]}).
-record(ts_inpevt_unicode, {code=0, action=down}).
-record(ts_inpevt_mouse, {action=move, buttons=[], point}).
-record(ts_inpevt_wheel, {clicks=0, point}).
-record(ts_input, {events=[]}).

-record(ts_session_info_logon, {domain, user, sessionid}).
-record(ts_session_info_error, {status}).

-record(ts_set_error_info, {info}).

-record(ts_autodetect_req, {flags=[], pdu}).
-record(ts_autodetect_resp, {flags=[], pdu}).

-record(rdp_rtt, {seq, type = postconnect}).
