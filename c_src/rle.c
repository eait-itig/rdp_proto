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

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "erl_nif.h"

#include "bitmap.h"

static ERL_NIF_TERM
uncompress(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary in, out, temp;
	ERL_NIF_TERM err;
	int ret, w, h, bpp, outbpp;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	memset(&temp, 0, sizeof(temp));

	if (!enif_inspect_binary(env, argv[0], &in)) {
		err = enif_make_atom(env, "bad_data");
		goto fail;
	}
	if (!enif_get_int(env, argv[1], &w)) {
		err = enif_make_atom(env, "bad_width");
		goto fail;
	}
	if (!enif_get_int(env, argv[2], &h)) {
		err = enif_make_atom(env, "bad_height");
		goto fail;
	}
	if (!enif_get_int(env, argv[3], &bpp) ||
			!(bpp == 16 || bpp == 24)) {
		err = enif_make_atom(env, "bad_bpp");
		goto fail;
	}

	outbpp = (bpp == 24) ? 32 : bpp;

	assert(enif_alloc_binary(w*h*outbpp/8, &out));

	ret = bitmap_decompress(in.data, out.data, w, h, in.size,
		bpp, outbpp);

	if (ret <= 0) {
		err = enif_make_atom(env, "decompress_failure");
		goto fail;
	}

	/*assert(enif_alloc_binary(w*h*4, &out));
	for (i = 0, j = 0; i < w*h; ++i, j += 3) {
		uint32_t k = 0;
		k |= temp.data[j];
		k |= temp.data[j+1] << 8;
		k |= temp.data[j+2] << 16;
		((uint32_t *)out.data)[i] = k;
	}

	enif_release_binary(&temp);*/

	return enif_make_tuple2(env,
		enif_make_atom(env, "ok"),
		enif_make_binary(env, &out));
fail:
	if (out.data != NULL)
		enif_release_binary(&out);
	return enif_make_tuple2(env,
		enif_make_atom(env, "error"), err);
}

static ERL_NIF_TERM
compress(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary in;
	ERL_NIF_TERM err;
	int w, h, ret, bpp;
	struct stream out, temp;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	memset(&temp, 0, sizeof(temp));

	if (!enif_inspect_binary(env, argv[0], &in)) {
		err = enif_make_atom(env, "bad_data");
		goto fail;
	}
	if (!enif_get_int(env, argv[1], &w)) {
		err = enif_make_atom(env, "bad_width");
		goto fail;
	}
	if (!enif_get_int(env, argv[2], &h)) {
		err = enif_make_atom(env, "bad_height");
		goto fail;
	}
	if (!enif_get_int(env, argv[3], &bpp) ||
			!(bpp == 16 || bpp == 24)) {
		err = enif_make_atom(env, "bad_bpp");
		goto fail;
	}
	if (in.size < w * h * bpp / 8) {
		err = enif_make_atom(env, "bad_size");
		goto fail;
	}

	assert(enif_alloc_binary(1*1024*1024, &out.bin));
	assert(enif_alloc_binary(1*1024*1024, &temp.bin));

	ret = xrdp_bitmap_compress((char *)in.data, w, h,
		&out, bpp, 1*1024*1024, &temp);
	if (ret <= 0) {
		err = enif_make_atom(env, "no_lines_sent");
		goto fail;
	}

	enif_release_binary(&temp.bin);
	assert(enif_alloc_binary(out.pos, &temp.bin));
	memcpy(temp.bin.data, out.bin.data, out.pos);
	enif_release_binary(&out.bin);

	return enif_make_tuple2(env,
		enif_make_atom(env, "ok"),
		enif_make_binary(env, &temp.bin));

fail:
	if (out.bin.data != NULL)
		enif_release_binary(&out.bin);
	if (temp.bin.data != NULL)
		enif_release_binary(&temp.bin);
	return enif_make_tuple2(env,
		enif_make_atom(env, "error"), err);
}

static int
load_cb(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	return 0;
}

static void
unload_cb(ErlNifEnv *env, void *priv_data)
{
}

static ErlNifFunc nif_funcs[] =
{
	{"compress", 4, compress},
	{"uncompress", 4, uncompress}
};

ERL_NIF_INIT(rle_nif, nif_funcs, load_cb, NULL, NULL, unload_cb)
