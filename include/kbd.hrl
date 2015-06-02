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

-ifndef(KBD_MACROS).

-define(KBDL_US, 16#409).
-define(KBDL_US_DVORAK, 16#10409).

-define(KBD_IBM83, 16#01).
-define(KBD_ICO102, 16#02).
-define(KBD_IBM84, 16#03).
-define(KBD_IBM101, 16#04).
-define(KBD_JAPAN, 16#07).

-define(KBD_SCANCODES, {
	null, esc, {$1, $!}, {$2, $@}, 			%  0
	{$3, $#}, {$4, $$}, {$5, $%}, {$6, $^}, %  4
	{$7, $&}, {$8, $*}, {$9, $(}, {$0, $)}, %  8
	{$-, $_}, {$=, $+}, bksp, tab, 			% 12
	{$q, $Q}, {$w, $W}, {$e, $E}, {$r, $R}, % 16
	{$t, $T}, {$y, $Y}, {$u, $U}, {$i, $I}, % 20
	{$o, $O}, {$p, $P}, {$[, ${}, {$], $}}, % 24
	enter, ctrl, {$a, $A}, {$s, $S},		% 28
	{$d, $D}, {$f, $F}, {$g, $G}, {$h, $H},	% 32
	{$j, $J}, {$k, $K}, {$l, $L}, {$;, $:}, % 36
	{$', $"}, {$`, $~}, shift, {$\\, $|},	% 40
	{$z, $Z}, {$x, $X}, {$c, $C}, {$v, $V},	% 44
	{$b, $B}, {$n, $N}, {$m, $M}, {$,, $<}, % 48
	{$., $>}, {$/, $?}, shift, prisc,		% 52
	alt, space, caps, f1,					% 56
	f2, f3, f4, f5,							% 60
	f6, f7, f8, f9,							% 64
	f10, num, scroll, home,					% 68
	up, pgup, 'gray-', left,				% 72
	center, right, 'gray+', 'end',			% 76
	down, pgdown, ins, del,					% 80
	null, null, null, f11,					% 84
	f12, null, null, null					% 88
	}).

-define(KBD_MACROS, 1).
-endif.
