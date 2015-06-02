/*
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
*/

#if !defined(_BITMAP_H)
#define _BITMAP_H

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "erl_nif.h"

struct stream {
	ErlNifBinary bin;
	int pos;
};

typedef uint32_t UINT32;
typedef uint16_t UINT16;
typedef int BOOL;
typedef uint8_t BYTE;
#define INLINE inline
#define TRUE 1
#define FALSE 0

#define CopyMemory memmove

static inline void *
_aligned_malloc(size_t s, size_t align)
{
	size_t pad = s % align;
	if (pad > 0)
		pad = align - pad;
	void *ptr = malloc(s + pad);
	assert((uint64_t)ptr % align == 0);
	return ptr;
}

static inline void
_aligned_free(void *ptr)
{
	free(ptr);
}

static inline void
init_stream(struct stream *s, int size)
{
	assert(size < s->bin.size);
	s->pos = 0;
}

static inline int
get_pos(struct stream *s)
{
	return s->pos;
}

static inline void
out_uint8(struct stream *s, uint8_t v)
{
	assert(s->pos + 1 < s->bin.size);
	s->bin.data[s->pos++] = v;
}

static inline void
out_uint16_le(struct stream *s, uint16_t v)
{
	assert(s->pos + 2 < s->bin.size);
	s->bin.data[s->pos++] = v & 0xff;
	s->bin.data[s->pos++] = (v >> 8) & 0xff;
}

static inline void
out_uint8a(struct stream *s, char *data, int n)
{
	assert(s->pos + n < s->bin.size);
	memcpy(&s->bin.data[s->pos], data, n);
	s->pos += n;
}

static inline char *
get_ptr(struct stream *s)
{
	return (char *)&s->bin.data[s->pos];
}

static inline char *
get_data(struct stream *s)
{
	return (char *)s->bin.data;
}

int xrdp_bitmap_compress(char *in_data, int width, int height,
                     struct stream *s, int bpp, int byte_limit,
                     struct stream *temp_s);

BOOL bitmap_decompress(BYTE* srcData, BYTE* dstData, int width, int height, int size, int srcBpp, int dstBpp);

#endif
