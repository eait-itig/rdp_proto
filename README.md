Ever wanted to make a Remote Desktop (RDP) server in Erlang? No? WHY NOT?

Hopefully this library can make your life a bit easier if you do.

### Protocol support

 * Currently only supports clients in TLS/SSL mode *without* CredSSP (this is all major open-source clients, as well as most closed-source ones including official clients from Microsoft)
 * Supports 16-bit and 24-bit colour
 * Old-style RLE bitmap compression (no RemoteFX or NSCodec support yet)
 * Fastpath support for input and updates
 * Revectoring/redirection support
 * Some basic clipboard integration (CLIPRDR)

### Known to work with (clients)

 * Official MS clients for Windows, OSX, iOS and Android
 * XFreeRDP / FreeRDP (for Linux)
 * rdesktop (only the very last version with some extra patches, there may be bugs)

### License

2-clause BSD

### How to use it

The easiest way is to make use of the `rdp_server` behaviour. There's a built-in acceptor pool implementation for the server, too.

First, choose a name for your callback module. We'll call ours `rdpserv` (because we're very imaginative). Add a child spec to your supervisor like this:

```erlang
{rdpserv_sup,
    {rdp_server_sup, start_link, [3389, rdpserv]},
    permanent, infinity, supervisor, [rdpserv, rdp_server, rdp_server_sup, rdp_server_fsm]}
```

Now a basic boilerplate implementation of the behaviour:

```erlang
-module(rdpserv).
-behaviour(rdp_server).

-include_lib("rdp_proto/include/rdp_server.hrl").

-export([
    init/1,
    handle_connect/4,
    init_ui/2,
    handle_event/3,
    terminate/2
    ]).

-record(state, {}).

%% @arg Peer  the peer address (IPv4 or IPv6) connecting
init(_Peer) ->
    {ok, #state{}}.

handle_connect(Cookie, Protocols, Srv, S = #state{}) ->
    % returns either
    {reject, S}.
    % or
    {accept, SslOptions, S}.
    % SslOptions should probably contain at least [{certfile, ...}, {keyfile, ...}]

init_ui(Srv, S = #state{}) ->
    % draw your initial ui here, eg:
    ok = rdp_server:send_update(Srv, #ts_update_orders{orders = [
            #ts_order_opaquerect{
                dest = {0,0}, size = {100,100},
                color = {100, 0, 0}  % red,green,blue 0-255
            }
        ]}),
    {ok, S}.

handle_event(#ts_inpevt_mouse{point = {X,Y}, action=move}, Srv, S = #state{}) ->
    % handle a mouse movement event, react by redrawing part of your ui
    % etc etc
    {ok, S}.

terminate(_Reason, #state{}) ->
    % any cleanup you need to do at exit
    ok.
```

Most servers will prefer to use bitmap updates rather than `#ts_update_orders{}`, as orders are less portable across clients. You can see example code for composing bitmap update orders in the `rdp_ui` repository.

### "Raw" mode and proxying

The `rdp_server` behaviour is also built to enable proxying to a backend server (as this is how the `rdpproxy` project uses it). Instead of returning `{accept, SslOptions, State}` from `handle_connect/4`, you can also return `{accept_raw, State}`.

From this point onwards, the `rdp_server_fsm` will stop decoding protocol traffic itself and instead give you raw binaries of the incoming data.

You can then decode these to records yourself by passing them through `rdpp:decode_server/1`, or simply proxy them through to a backend connection.

### Lower-level protocol tools

The other modules in the library can be used on their own as well as through `rdp_server`. The layers involved in the RDP protocol are:

 * TPKT packet format (`tpkt:encode`, as well as built-in support in `gen_tcp`)
 * X224 protocol (`x224:encode` and `x224:decode`)
 * MCS/GCC protocol (`mcsgcc:encode` and `mcsgcc:decode`)
 * RDP "fastpath" (`fastpath:encode` and `fastpath:decode`)
 * RDP sharecontrol (`rdpp:encode_sharecontrol` etc)
 * RDP "basic" (`rdpp:encode_basic` etc)

Each of these contain their own PDU formats and are normally stacked together. For example, most screen update traffic is encoded under RDP sharecontrol, then MCS/GCC, then X224, then TPKT.

It was decided at some point that all this encapsulation was "too slow", so if available, there is also the RDP "fastpath" encoding, which encodes screen updates and inputs in a format that can go directly onto the wire.

There are also encoder/decoder modules for:

 * TSUDs ("TS User Data", the early capability exchange units that are stapled onto MCS/GCC initialisation)
 * TSCAPs ("TS Capability Sets", stapled onto TS_DEMAND and TS_CONFIRM PDUs).

You can find out a lot more information about all of this and the organisation of the protocol by reading through the documents linked on the FreeRDP wiki: https://github.com/FreeRDP/FreeRDP/wiki/Reference-Documentation

The code of the `rdp_server_fsm` module can also be quite helpful.

### Future development

 * NSCodec support and surface updates (the beginnings of this are already in the code but not working yet)
 * Make the RLE encoding NIF into a dirty NIF if available on OTP R17 and later
 * Implement some more DVC sub-protocols like the CLIPRDR
 * More colour modes
 * ???
