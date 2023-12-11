/*
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
*/

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "erl_nif.h"
#include "mppc.h"

static ErlNifResourceType *mppc_ctx_rsrc;

struct mppc_ctx {
	ErlNifMutex		*mc_lock;
	MPPC_CONTEXT		*mc_ctx;
	uint32_t		 mc_level;
	uint8_t			*mc_tbuf;
	size_t			 mc_tsz;
};

static void
mppc_ctx_dtor(ErlNifEnv *env, void *arg)
{
	struct mppc_ctx *ctx = arg;
	enif_mutex_lock(ctx->mc_lock);
	mppc_context_free(ctx->mc_ctx);
	ctx->mc_ctx = NULL;
	free(ctx->mc_tbuf);
	ctx->mc_tbuf = NULL;
	ctx->mc_tsz = 0;
	enif_mutex_unlock(ctx->mc_lock);
	enif_mutex_destroy(ctx->mc_lock);
	ctx->mc_lock = NULL;
}

static ERL_NIF_TERM
mppcnif_new_context(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct mppc_ctx *mc;
	char atom[16];
	BOOL compressor;
	ERL_NIF_TERM rv;

	if (argc != 1)
		return (enif_make_badarg(env));

	if (!enif_get_atom(env, argv[0], atom, sizeof (atom), ERL_NIF_LATIN1))
		return (enif_make_badarg(env));

	if (strcmp(atom, "compress") == 0)
		compressor = TRUE;
	else if (strcmp(atom, "decompress") == 0)
		compressor = FALSE;
	else
		return (enif_make_badarg(env));

	mc = enif_alloc_resource(mppc_ctx_rsrc, sizeof (*mc));
	bzero(mc, sizeof (*mc));
	mc->mc_lock = enif_mutex_create("mppc_ctx");
	mc->mc_level = 0;
	mc->mc_ctx = mppc_context_new(0, compressor);
	mc->mc_tsz = 8192;
	mc->mc_tbuf = malloc(mc->mc_tsz);

	rv = enif_make_resource(env, mc);
	enif_release_resource(mc);

	return (enif_make_tuple2(env, enif_make_atom(env, "ok"), rv));
}

static ERL_NIF_TERM
mppcnif_set_level(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct mppc_ctx *mc;
	char atom[16];
	uint32_t level;

	if (argc != 2)
		return (enif_make_badarg(env));
	if (!enif_get_resource(env, argv[0], mppc_ctx_rsrc, (void **)&mc))
		return (enif_make_badarg(env));
	if (!enif_get_atom(env, argv[1], atom, sizeof (atom), ERL_NIF_LATIN1))
		return (enif_make_badarg(env));
	if (strcmp(atom, "8k") == 0)
		level = 0;
	else if (strcmp(atom, "64k") == 0)
		level = 1;
	else
		return (enif_make_badarg(env));

	enif_mutex_lock(mc->mc_lock);
	mc->mc_level = level;
	mppc_set_compression_level(mc->mc_ctx, level);
	enif_mutex_unlock(mc->mc_lock);

	return (enif_make_atom(env, "ok"));
}

static ERL_NIF_TERM
mppcnif_get_level(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct mppc_ctx *mc;
	uint32_t level;

	if (argc != 1)
		return (enif_make_badarg(env));
	if (!enif_get_resource(env, argv[0], mppc_ctx_rsrc, (void **)&mc))
		return (enif_make_badarg(env));

	enif_mutex_lock(mc->mc_lock);
	level = mc->mc_level;
	enif_mutex_unlock(mc->mc_lock);

	switch (level) {
	case 0:
		return (enif_make_atom(env, "8k"));
	case 1:
		return (enif_make_atom(env, "64k"));
	default:
		return (enif_raise_exception(env,
		    enif_make_atom(env, "unknown_level")));
	}
}

static ERL_NIF_TERM
mppcnif_compress(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct mppc_ctx *mc;
	ErlNifBinary bin, outbin;
	int rc;
	const uint8_t *out;
	uint32_t sz;
	uint32_t flags;
	ERL_NIF_TERM flaglist, rv;

	if (argc != 2)
		return (enif_make_badarg(env));
	if (!enif_get_resource(env, argv[0], mppc_ctx_rsrc, (void **)&mc))
		return (enif_make_badarg(env));
	if (!enif_inspect_iolist_as_binary(env, argv[1], &bin))
		return (enif_make_badarg(env));
	if (bin.size < 1)
		return (enif_make_badarg(env));

	rc = enif_alloc_binary(bin.size, &outbin);
	assert(rc);
	sz = bin.size;

	enif_mutex_lock(mc->mc_lock);

	while (mc->mc_tsz < sz) {
		mc->mc_tsz *= 2;
		free(mc->mc_tbuf);
		mc->mc_tbuf = malloc(mc->mc_tsz);
	}

	rc = mppc_compress(mc->mc_ctx, bin.data, bin.size, mc->mc_tbuf, &out,
	    &sz, &flags);

	if (rc == -1) {
		enif_release_binary(&outbin);
		enif_mutex_unlock(mc->mc_lock);
		return (enif_raise_exception(env,
		    enif_make_atom(env, "mppc_compress_fail")));
	}


	bcopy(out, outbin.data, sz);

	enif_mutex_unlock(mc->mc_lock);

	if (sz != outbin.size)
		enif_realloc_binary(&outbin, sz);
	rv = enif_make_binary(env, &outbin);

	flaglist = enif_make_list(env, 0);
	if (flags & PACKET_COMPRESSED)
		flaglist = enif_make_list_cell(env,
		    enif_make_atom(env, "compressed"), flaglist);
	if (flags & PACKET_AT_FRONT)
		flaglist = enif_make_list_cell(env,
		    enif_make_atom(env, "at_front"), flaglist);
	if (flags & PACKET_FLUSHED)
		flaglist = enif_make_list_cell(env,
		    enif_make_atom(env, "flushed"), flaglist);

	return (enif_make_tuple3(env,
	    enif_make_atom(env, "ok"), rv, flaglist));
}

static ERL_NIF_TERM
mppcnif_decompress(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	return (enif_make_badarg(env));
}

static ERL_NIF_TERM
mppcnif_reset(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	struct mppc_ctx *mc;
	char atom[16];
	BOOL flush;

	if (argc != 2)
		return (enif_make_badarg(env));
	if (!enif_get_resource(env, argv[0], mppc_ctx_rsrc, (void **)&mc))
		return (enif_make_badarg(env));
	if (!enif_get_atom(env, argv[1], atom, sizeof (atom), ERL_NIF_LATIN1))
		return (enif_make_badarg(env));
	if (strcmp(atom, "true") == 0)
		flush = TRUE;
	else if (strcmp(atom, "false") == 0)
		flush = FALSE;
	else
		return (enif_make_badarg(env));

	enif_mutex_lock(mc->mc_lock);
	mppc_context_reset(mc->mc_ctx, flush);
	enif_mutex_unlock(mc->mc_lock);

	return (enif_make_atom(env, "ok"));
}

static int
load_cb(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	mppc_ctx_rsrc = enif_open_resource_type(env, NULL, "mppc_ctx",
	    mppc_ctx_dtor, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
	    NULL);
	return 0;
}

static void
unload_cb(ErlNifEnv *env, void *priv_data)
{
}

static ErlNifFunc nif_funcs[] =
{
	{ "new_context",	1, mppcnif_new_context },
	{ "set_level",		2, mppcnif_set_level },
	{ "compress",		2, mppcnif_compress },
	{ "decompress",		3, mppcnif_decompress },
	{ "reset",		2, mppcnif_reset },
	{ "get_level",		1, mppcnif_get_level },
};

ERL_NIF_INIT(mppc_nif, nif_funcs, load_cb, NULL, NULL, unload_cb)
