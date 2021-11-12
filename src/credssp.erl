%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2012-2021 Alex Wilson <alex@uq.edu.au>
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

-module(credssp).

-compile([{parse_transform, lager_transform}]).
-include_lib("public_key/include/public_key.hrl").

-export([
    initiate/2,
    continue/2
    ]).

-include("credssp.hrl").

-record(?MODULE, {
    next :: continue | final,
    opts :: options(),
    gss :: gss_mechanism:state(),
    spki :: spki(),
    nonce :: undefined | binary()
    }).

-opaque state() :: #?MODULE{}.

-type options() :: #{
    ticket => krb_proto:ticket(),
    domain => binary(),
    username => binary(),
    password => binary()
    }.

-type spki() :: #'SubjectPublicKeyInfo'{}.
-type req() :: #'TSRequest'{}.
-type msg() :: binary().

-export_type([
    state/0
    ]).

-spec add_client_pkauth(req(), state()) -> {req(), state()}.
add_client_pkauth(Req0 = #'TSRequest'{}, S0 = #?MODULE{spki = SPKI,
                                                       gss = GSS0}) ->
    #'SubjectPublicKeyInfo'{subjectPublicKey = SPKData} = SPKI,
    Nonce = crypto:strong_rand_bytes(32),
    HashData = <<"CredSSP Client-To-Server Binding Hash", 0,
        Nonce/binary, SPKData/binary>>,
    Hash = crypto:hash(sha256, HashData),
    {ok, Token, GSS1} = gss_spnego:wrap(Hash, GSS0),
    Req1 = Req0#'TSRequest'{
        clientNonce = Nonce,
        pubKeyAuth = Token
    },
    S1 = S0#?MODULE{gss = GSS1, nonce = Nonce},
    {Req1, S1}.

-spec verify_server_pkauth(req(), state()) -> {boolean(), state()}.
verify_server_pkauth(Req = #'TSRequest'{}, S0 = #?MODULE{spki = SPKI,
                                                         gss = GSS0,
                                                         nonce = Nonce}) ->
    #'TSRequest'{pubKeyAuth = Token} = Req,
    #'SubjectPublicKeyInfo'{subjectPublicKey = SPKData} = SPKI,
    HashData = <<"CredSSP Server-To-Client Binding Hash", 0,
        Nonce/binary, SPKData/binary>>,
    OurHash = crypto:hash(sha256, HashData),
    case gss_spnego:unwrap(Token, GSS0) of
        {ok, TheirHash, GSS1} ->
            S1 = S0#?MODULE{gss = GSS1},
            OurHashHash = crypto:hash(sha512, OurHash),
            TheirHashHash = crypto:hash(sha512, TheirHash),
            case OurHashHash of
                TheirHashHash ->
                    {true, S1};
                _ ->
                    _ = lager:debug("CredSSP server pubKeyAuth hash does not "
                        "match ours: possible MITM attack!"),
                    {false, S1}
            end;
        {error, Why, GSS1} ->
            S1 = S0#?MODULE{gss = GSS1},
            _ = lager:debug("GSS error decrypting CredSSP server pubKeyAuth: "
                "~p", [Why]),
            {false, S1};
        {error, Why} ->
            _ = lager:debug("GSS fatal error decrypting CredSSP server "
                "pubKeyAuth: ~p", [Why]),
            {false, S0}
    end.

-spec initiate(spki(), options()) -> {continue, msg(), state()} | {error, term()}.
initiate(SPKI, Opts0) ->
    S0 = #?MODULE{spki = SPKI, opts = Opts0},
    Opts1 = Opts0#{
        chan_bindings => <<0:128/big>>,
        mutual_auth => true
    },
    case gss_spnego:initiate(Opts1) of
        {continue, Token0, GSS0} ->
            S1 = S0#?MODULE{gss = GSS0},
            Pdu = #'TSRequest'{
                version = 6,
                negoTokens = [
                    #'NegoData_SEQOF'{negoToken = Token0}
                ]
            },
            {ok, Bin} = credssp_ber:encode('TSRequest', Pdu),
            {continue, Bin, S1#?MODULE{next = continue}};

        {ok, Token0, GSS0} ->
            S1 = S0#?MODULE{gss = GSS0},
            Pdu0 = #'TSRequest'{
                version = 6,
                negoTokens = [
                    #'NegoData_SEQOF'{negoToken = Token0}
                ]
            },
            {Pdu1, S2} = add_client_pkauth(Pdu0, S1),
            {ok, Bin} = credssp_ber:encode('TSRequest', Pdu1),
            {continue, Bin, S2#?MODULE{next = final}};

        {error, Why} ->
            {error, {gss_error, Why}}
    end.

-spec continue(msg(), state()) ->
    {ok, state()} |
    {ok, msg(), state()} |
    {continue, msg(), state()} |
    {error, term()}.
continue(Data, S0 = #?MODULE{next = continue, gss = GSS0}) ->
    case credssp_ber:decode('TSRequest', Data) of
        {ok, #'TSRequest'{version = N}} when N < 5 ->
            {error, {credssp_version_too_old, N}};

        {ok, #'TSRequest'{errorCode = I}} when is_integer(I) ->
            {error, {credssp_remote_error, I}};

        {ok, #'TSRequest'{negoTokens = [#'NegoData_SEQOF'{negoToken = Token0}],
                          pubKeyAuth = asn1_NOVALUE}} ->
            Res = gss_spnego:continue(Token0, GSS0),
            case Res of
                {continue, Token1, GSS1} ->
                    Pdu = #'TSRequest'{
                        version = 6,
                        negoTokens = [
                            #'NegoData_SEQOF'{negoToken = Token1}
                        ]
                    },
                    {ok, OutBin} = credssp_ber:encode('TSRequest', Pdu),
                    {continue, OutBin, S0#?MODULE{gss = GSS1}};

                {ok, GSS1} ->
                    S1 = S0#?MODULE{gss = GSS1},
                    Pdu0 = #'TSRequest'{version = 6},
                    {Pdu1, S2} = add_client_pkauth(Pdu0, S1),
                    {ok, OutBin} = credssp_ber:encode('TSRequest', Pdu1),
                    {continue, OutBin, S2#?MODULE{next = final}};

                {ok, Token1, GSS1} ->
                    S1 = S0#?MODULE{gss = GSS1},
                    Pdu0 = #'TSRequest'{
                        version = 6,
                        negoTokens = [
                            #'NegoData_SEQOF'{negoToken = Token1}
                        ]
                    },
                    {Pdu1, S2} = add_client_pkauth(Pdu0, S1),
                    {ok, OutBin} = credssp_ber:encode('TSRequest', Pdu1),
                    {continue, OutBin, S2#?MODULE{next = final}};

                {error, Why} ->
                    {error, {gss_error, Why}}
            end;

        {error, Why} ->
            {error, {credssp_decode, Why}}
    end;

continue(Data, S0 = #?MODULE{next = final, opts = Opts}) ->
    case credssp_ber:decode('TSRequest', Data) of
        {ok, #'TSRequest'{version = N}} when N < 5 ->
            {error, {credssp_version_too_old, N}};

        {ok, #'TSRequest'{errorCode = I}} when is_integer(I) ->
            {error, {credssp_remote_error, I}};

        {ok, Req = #'TSRequest'{pubKeyAuth = PKAuth}} when is_binary(PKAuth) ->
            case verify_server_pkauth(Req, S0) of
                {true, S1 = #?MODULE{gss = GSS0}} ->
                    Domain = case Opts of
                        #{domain := D} -> D;
                        #{ticket := #{realm := R}} -> iolist_to_binary([R])
                    end,
                    Username = case Opts of
                        #{username := U} -> U;
                        #{ticket := #{principal := [UStr]}} ->
                            iolist_to_binary([UStr])
                    end,
                    Password = maps:get(password, Opts, <<>>),
                    PWCred = #'TSPasswordCreds'{
                        domainName = Domain,
                        userName = Username,
                        password = Password
                    },
                    {ok, PWCredBin} = credssp_ber:encode(
                        'TSPasswordCreds', PWCred),
                    Creds = #'TSCredentials'{
                        credType = password,
                        credentials = PWCredBin
                    },
                    {ok, CredsBin} = credssp_ber:encode('TSCredentials', Creds),
                    {ok, Token, GSS1} = gss_spnego:wrap(CredsBin, GSS0),
                    S2 = S1#?MODULE{gss = GSS1},
                    Req0 = #'TSRequest'{
                        version = 6,
                        authInfo = Token
                    },
                    {ok, OutBin} = credssp_ber:encode('TSRequest', Req0),
                    {ok, OutBin, S2};

                {false, _S1} ->
                    {error, credssp_pkauth_failed}
            end;

        {error, Why} ->
            {error, {tsreq_decode, Why}}
    end.
