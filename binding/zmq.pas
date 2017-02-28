//
// zmq.h header binding for the Free Pascal Compiler aka FPC
//
// Binaries and demos available at http://www.djmaster.com/
//

(*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    *************************************************************************
    NOTE to contributors. This file comprises the principal public contract
    for ZeroMQ API users. Any change to this file supplied in a stable
    release SHOULD not break existing applications.
    In practice this means that the value of constants must not change, and
    that old values may not be reused for new constants.
    *************************************************************************
*)

unit zmq;

{$mode objfpc}{$H+}

interface

uses

  ctypes{$ifdef MSWINDOWS}, winsock2{$endif};

const
{$ifdef MSWINDOWS}
  LIB_ZMQ = 'libzmq.dll';
{$else}
  LIB_ZMQ = 'libzmq.so';
{$endif}

// #ifndef __ZMQ_H_INCLUDED__
// #define __ZMQ_H_INCLUDED__

const
(*  Version macros for compile-time API version detection                     *)
  ZMQ_VERSION_MAJOR = 4;
  ZMQ_VERSION_MINOR = 2;
  ZMQ_VERSION_PATCH = 2;

//TODO #define ZMQ_MAKE_VERSION(major, minor, patch) \
//TODO     ((major) * 10000 + (minor) * 100 + (patch))
//TODO #define ZMQ_VERSION \
//TODO     ZMQ_MAKE_VERSION(ZMQ_VERSION_MAJOR, ZMQ_VERSION_MINOR, ZMQ_VERSION_PATCH)
const
  ZMQ_VERSION_H = ZMQ_VERSION_MAJOR*10000 + ZMQ_VERSION_MINOR*100 + ZMQ_VERSION_PATCH;

// #ifdef __cplusplus
// extern "C" {
// #endif

// #if !defined _WIN32_WCE
// #include <errno.h>
// #endif
// #include <stddef.h>
// #include <stdio.h>
// #if defined _WIN32
// //  Set target version to Windows Server 2008, Windows Vista or higher.
// //  Windows XP (0x0501) is supported but without client & server socket types.
// #ifndef _WIN32_WINNT
// #define _WIN32_WINNT 0x0600
// #endif

// #ifdef __MINGW32__
// //  Require Windows XP or higher with MinGW for getaddrinfo().
// #if(_WIN32_WINNT >= 0x0600)
// #else
// #undef _WIN32_WINNT
// #define _WIN32_WINNT 0x0600
// #endif
// #endif
// #include <winsock2.h>
// #endif

// (*  Handle DSO symbol visibility                                             *)
// #if defined _WIN32
// #   if defined ZMQ_STATIC
// #       define ZMQ_EXPORT
// #   elif defined DLL_EXPORT
// #       define ZMQ_EXPORT __declspec(dllexport)
// #   else
// #       define ZMQ_EXPORT __declspec(dllimport)
// #   endif
// #else
// #   if defined __SUNPRO_C  || defined __SUNPRO_CC
// #       define ZMQ_EXPORT __global
// #   elif (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
// #       define ZMQ_EXPORT __attribute__ ((visibility("default")))
// #   else
// #       define ZMQ_EXPORT
// #   endif
// #endif

//TODO /*  Define integer types needed for event interface                          */
//TODO #define ZMQ_DEFINED_STDINT 1
//TODO #if defined ZMQ_HAVE_SOLARIS || defined ZMQ_HAVE_OPENVMS
//TODO #   include <inttypes.h>
//TODO #elif defined _MSC_VER && _MSC_VER < 1600
//TODO #   ifndef int32_t
//TODO         typedef __int32 int32_t;
//TODO #   endif
//TODO #   ifndef uint16_t
//TODO         typedef unsigned __int16 uint16_t;
//TODO #   endif
//TODO #   ifndef uint8_t
//TODO         typedef unsigned __int8 uint8_t;
//TODO #   endif
//TODO #else
//TODO #   include <stdint.h>
//TODO #endif

// //  32-bit AIX's pollfd struct members are called reqevents and rtnevents so it
// //  defines compatibility macros for them. Need to include that header first to
// //  stop build failures since zmq_pollset_t defines them as events and revents.
// #ifdef ZMQ_HAVE_AIX
//     #include <poll.h>
// #endif

(******************************************************************************)
(*  0MQ errors.                                                               *)
(******************************************************************************)

const
(*  A number random enough not to collide with different errno ranges on      *)
(*  different OSes. The assumption is that error_t is at least 32-bit type.   *)
  ZMQ_HAUSNUMERO = 156384712;

(*  On Windows platform some of the standard POSIX errnos are not defined.    *)
{$ifdef MSWINDOWS}
  ENOTSUP = (ZMQ_HAUSNUMERO + 1);
  EPROTONOSUPPORT = (ZMQ_HAUSNUMERO + 2);
  ENOBUFS = (ZMQ_HAUSNUMERO + 3);
  ENETDOWN = (ZMQ_HAUSNUMERO + 4);
  EADDRINUSE = (ZMQ_HAUSNUMERO + 5);
  EADDRNOTAVAIL = (ZMQ_HAUSNUMERO + 6);
  ECONNREFUSED = (ZMQ_HAUSNUMERO + 7);
  EINPROGRESS = (ZMQ_HAUSNUMERO + 8);
  ENOTSOCK = (ZMQ_HAUSNUMERO + 9);
  EMSGSIZE = (ZMQ_HAUSNUMERO + 10);
  EAFNOSUPPORT = (ZMQ_HAUSNUMERO + 11);
  ENETUNREACH = (ZMQ_HAUSNUMERO + 12);
  ECONNABORTED = (ZMQ_HAUSNUMERO + 13);
  ECONNRESET = (ZMQ_HAUSNUMERO + 14);
  ENOTCONN = (ZMQ_HAUSNUMERO + 15);
  ETIMEDOUT = (ZMQ_HAUSNUMERO + 16);
  EHOSTUNREACH = (ZMQ_HAUSNUMERO + 17);
  ENETRESET = (ZMQ_HAUSNUMERO + 18);
{$endif}

(*  Native 0MQ error codes.                                                   *)
  EFSM = (ZMQ_HAUSNUMERO + 51);
  ENOCOMPATPROTO = (ZMQ_HAUSNUMERO + 52);
  ETERM = (ZMQ_HAUSNUMERO + 53);
  EMTHREAD = (ZMQ_HAUSNUMERO + 54);

(*  This function retrieves the errno as it is known to 0MQ library. The goal *)
(*  of this function is to make the code 100% portable, including where 0MQ   *)
(*  compiled with certain CRT library (on Windows) is linked to an            *)
(*  application that uses different CRT library.                              *)
function zmq_errno(): cint; cdecl; external LIB_ZMQ;

(*  Resolves system errors and 0MQ errors to human-readable string.           *)
function zmq_strerror(errnum: cint): pchar; cdecl; external LIB_ZMQ;

(*  Run-time API version detection                                            *)
procedure zmq_version(major: pcint; minor: pcint; patch: pcint); cdecl; external LIB_ZMQ;

(******************************************************************************)
(*  0MQ infrastructure (a.k.a. context) initialisation & termination.         *)
(******************************************************************************)

(*  New API                                                                   *)
const
(*  Context options                                                           *)
  ZMQ_IO_THREADS = 1;
  ZMQ_MAX_SOCKETS = 2;
  ZMQ_SOCKET_LIMIT = 3;
  ZMQ_THREAD_PRIORITY = 3;
  ZMQ_THREAD_SCHED_POLICY = 4;
  ZMQ_MAX_MSGSZ = 5;

(*  Default for new contexts                                                  *)
  ZMQ_IO_THREADS_DFLT = 1;
  ZMQ_MAX_SOCKETS_DFLT = 1023;
  ZMQ_THREAD_PRIORITY_DFLT = -1;
  ZMQ_THREAD_SCHED_POLICY_DFLT = -1;

function zmq_ctx_new(): pointer; cdecl; external LIB_ZMQ;
function zmq_ctx_term(context: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_ctx_shutdown(context: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_ctx_set(context: pointer; option: cint; optval: cint): cint; cdecl; external LIB_ZMQ;
function zmq_ctx_get(context: pointer; option: cint): cint; cdecl; external LIB_ZMQ;

(*  Old (legacy) API                                                          *)
function zmq_init(io_threads: cint): pointer; cdecl; external LIB_ZMQ;
function zmq_term(context: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_ctx_destroy(context: pointer): cint; cdecl; external LIB_ZMQ;

(******************************************************************************)
(*  0MQ message definition.                                                   *)
(******************************************************************************)

type
(* Some architectures, like sparc64 and some variants of aarch64, enforce pointer
 * alignment and raise sigbus on violations. Make sure applications allocate
 * zmq_msg_t on addresses aligned on a pointer-size boundary to avoid this issue.
 *)
  Pzmq_msg_t = ^zmq_msg_t;
  zmq_msg_t = record
    _: array[0..63] of cuchar;
  end;

  Pzmq_free_fn = ^zmq_free_fn;
  zmq_free_fn = procedure (data: pointer; hint: pointer); cdecl;

function zmq_msg_init(msg: Pzmq_msg_t): cint; cdecl; external LIB_ZMQ;
function zmq_msg_init_size(msg: Pzmq_msg_t; size: csize_t): cint; cdecl; external LIB_ZMQ;
function zmq_msg_init_data(msg: Pzmq_msg_t; data: pointer; size: csize_t; ffn: Pzmq_free_fn; hint: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_msg_send(msg: Pzmq_msg_t; s: pointer; flags: cint): cint; cdecl; external LIB_ZMQ;
function zmq_msg_recv(msg: Pzmq_msg_t; s: pointer; flags: cint): cint; cdecl; external LIB_ZMQ;
function zmq_msg_close(msg: Pzmq_msg_t): cint; cdecl; external LIB_ZMQ;
function zmq_msg_move(dest: Pzmq_msg_t; src: Pzmq_msg_t): cint; cdecl; external LIB_ZMQ;
function zmq_msg_copy(dest: Pzmq_msg_t; src: Pzmq_msg_t): cint; cdecl; external LIB_ZMQ;
function zmq_msg_data(msg: Pzmq_msg_t): pointer; cdecl; external LIB_ZMQ;
FUNCTION zmq_msg_size(msg: Pzmq_msg_t): csize_t; cdecl; external LIB_ZMQ;
function zmq_msg_more(msg: Pzmq_msg_t): cint; cdecl; external LIB_ZMQ;
function zmq_msg_get(msg: Pzmq_msg_t; property_: cint): cint; cdecl; external LIB_ZMQ;
function zmq_msg_set(msg: Pzmq_msg_t; property_: cint; optval: cint): cint; cdecl; external LIB_ZMQ;
function zmq_msg_gets(msg: Pzmq_msg_t; const property_: pchar): pchar; cdecl; external LIB_ZMQ;


(******************************************************************************)
(*  0MQ socket definition.                                                    *)
(******************************************************************************)

const
(*  Socket types.                                                             *)
  ZMQ_PAIR = 0;
  ZMQ_PUB = 1;
  ZMQ_SUB = 2;
  ZMQ_REQ = 3;
  ZMQ_REP = 4;
  ZMQ_DEALER = 5;
  ZMQ_ROUTER = 6;
  ZMQ_PULL = 7;
  ZMQ_PUSH = 8;
  ZMQ_XPUB = 9;
  ZMQ_XSUB = 10;
  ZMQ_STREAM = 11;

(*  Deprecated aliases                                                        *)
  ZMQ_XREQ = ZMQ_DEALER deprecated;
  ZMQ_XREP = ZMQ_ROUTER deprecated;

(*  Socket options.                                                           *)
  ZMQ_AFFINITY = 4;
  ZMQ_IDENTITY = 5;
  ZMQ_SUBSCRIBE = 6;
  ZMQ_UNSUBSCRIBE = 7;
  ZMQ_RATE = 8;
  ZMQ_RECOVERY_IVL = 9;
  ZMQ_SNDBUF = 11;
  ZMQ_RCVBUF = 12;
  ZMQ_RCVMORE = 13;
  ZMQ_FD = 14;
  ZMQ_EVENTS = 15;
  ZMQ_TYPE = 16;
  ZMQ_LINGER = 17;
  ZMQ_RECONNECT_IVL = 18;
  ZMQ_BACKLOG = 19;
  ZMQ_RECONNECT_IVL_MAX = 21;
  ZMQ_MAXMSGSIZE = 22;
  ZMQ_SNDHWM = 23;
  ZMQ_RCVHWM = 24;
  ZMQ_MULTICAST_HOPS = 25;
  ZMQ_RCVTIMEO = 27;
  ZMQ_SNDTIMEO = 28;
  ZMQ_LAST_ENDPOINT = 32;
  ZMQ_ROUTER_MANDATORY = 33;
  ZMQ_TCP_KEEPALIVE = 34;
  ZMQ_TCP_KEEPALIVE_CNT = 35;
  ZMQ_TCP_KEEPALIVE_IDLE = 36;
  ZMQ_TCP_KEEPALIVE_INTVL = 37;
  ZMQ_IMMEDIATE = 39;
  ZMQ_XPUB_VERBOSE = 40;
  ZMQ_ROUTER_RAW = 41;
  ZMQ_IPV6 = 42;
  ZMQ_MECHANISM = 43;
  ZMQ_PLAIN_SERVER = 44;
  ZMQ_PLAIN_USERNAME = 45;
  ZMQ_PLAIN_PASSWORD = 46;
  ZMQ_CURVE_SERVER = 47;
  ZMQ_CURVE_PUBLICKEY = 48;
  ZMQ_CURVE_SECRETKEY = 49;
  ZMQ_CURVE_SERVERKEY = 50;
  ZMQ_PROBE_ROUTER = 51;
  ZMQ_REQ_CORRELATE = 52;
  ZMQ_REQ_RELAXED = 53;
  ZMQ_CONFLATE = 54;
  ZMQ_ZAP_DOMAIN = 55;
  ZMQ_ROUTER_HANDOVER = 56;
  ZMQ_TOS = 57;
  ZMQ_CONNECT_RID = 61;
  ZMQ_GSSAPI_SERVER = 62;
  ZMQ_GSSAPI_PRINCIPAL = 63;
  ZMQ_GSSAPI_SERVICE_PRINCIPAL = 64;
  ZMQ_GSSAPI_PLAINTEXT = 65;
  ZMQ_HANDSHAKE_IVL = 66;
  ZMQ_SOCKS_PROXY = 68;
  ZMQ_XPUB_NODROP = 69;
  ZMQ_BLOCKY = 70;
  ZMQ_XPUB_MANUAL = 71;
  ZMQ_XPUB_WELCOME_MSG = 72;
  ZMQ_STREAM_NOTIFY = 73;
  ZMQ_INVERT_MATCHING = 74;
  ZMQ_HEARTBEAT_IVL = 75;
  ZMQ_HEARTBEAT_TTL = 76;
  ZMQ_HEARTBEAT_TIMEOUT = 77;
  ZMQ_XPUB_VERBOSER = 78;
  ZMQ_CONNECT_TIMEOUT = 79;
  ZMQ_TCP_MAXRT = 80;
  ZMQ_THREAD_SAFE = 81;
  ZMQ_MULTICAST_MAXTPDU = 84;
  ZMQ_VMCI_BUFFER_SIZE = 85;
  ZMQ_VMCI_BUFFER_MIN_SIZE = 86;
  ZMQ_VMCI_BUFFER_MAX_SIZE = 87;
  ZMQ_VMCI_CONNECT_TIMEOUT = 88;
  ZMQ_USE_FD = 89;

(*  Message options                                                           *)
  ZMQ_MORE = 1;
  ZMQ_SHARED = 3;

(*  Send/recv options.                                                        *)
  ZMQ_DONTWAIT = 1;
  ZMQ_SNDMORE = 2;

(*  Security mechanisms                                                       *)
  ZMQ_NULL = 0;
  ZMQ_PLAIN = 1;
  ZMQ_CURVE = 2;
  ZMQ_GSSAPI = 3;

(*  RADIO-DISH protocol                                                       *)
  ZMQ_GROUP_MAX_LENGTH = 15;

(*  Deprecated options and aliases                                            *)
  ZMQ_TCP_ACCEPT_FILTER       = 38 deprecated;
  ZMQ_IPC_FILTER_PID          = 58 deprecated;
  ZMQ_IPC_FILTER_UID          = 59 deprecated;
  ZMQ_IPC_FILTER_GID          = 60 deprecated;
  ZMQ_IPV4ONLY                = 31 deprecated;
  ZMQ_DELAY_ATTACH_ON_CONNECT = ZMQ_IMMEDIATE deprecated;
  ZMQ_NOBLOCK                 = ZMQ_DONTWAIT deprecated;
  ZMQ_FAIL_UNROUTABLE         = ZMQ_ROUTER_MANDATORY deprecated;
  ZMQ_ROUTER_BEHAVIOR         = ZMQ_ROUTER_MANDATORY deprecated;

(*  Deprecated Message options                                                *)
  ZMQ_SRCFD = 2 deprecated;

(******************************************************************************)
(*  0MQ socket events and monitoring                                          *)
(******************************************************************************)

(*  Socket transport events (TCP, IPC and TIPC only)                          *)

  ZMQ_EVENT_CONNECTED         = $0001;
  ZMQ_EVENT_CONNECT_DELAYED   = $0002;
  ZMQ_EVENT_CONNECT_RETRIED   = $0004;
  ZMQ_EVENT_LISTENING         = $0008;
  ZMQ_EVENT_BIND_FAILED       = $0010;
  ZMQ_EVENT_ACCEPTED          = $0020;
  ZMQ_EVENT_ACCEPT_FAILED     = $0040;
  ZMQ_EVENT_CLOSED            = $0080;
  ZMQ_EVENT_CLOSE_FAILED      = $0100;
  ZMQ_EVENT_DISCONNECTED      = $0200;
  ZMQ_EVENT_MONITOR_STOPPED   = $0400;
  ZMQ_EVENT_ALL               = $FFFF;

function zmq_socket(context: pointer; type_: cint): pointer; cdecl; external LIB_ZMQ;
function zmq_close(s: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_setsockopt(s: pointer; option: cint; const optval: pointer; optvallen: csize_t): cint; cdecl; external LIB_ZMQ;
function zmq_getsockopt(s: pointer; option: cint; optval: pointer; optvallen: pcsize_t): cint; cdecl; external LIB_ZMQ;
function zmq_bind(s: pointer; const addr: pchar): cint; cdecl; external LIB_ZMQ;
function zmq_connect(s: pointer; const addr: pchar): cint; cdecl; external LIB_ZMQ;
function zmq_unbind(s: pointer; const addr: pchar): cint; cdecl; external LIB_ZMQ;
function zmq_disconnect(s: pointer; const addr: pchar): cint; cdecl; external LIB_ZMQ;
function zmq_send(s: pointer; const buf: pointer; len: csize_t; flags: cint): cint; cdecl; external LIB_ZMQ;
function zmq_send_const(s: pointer; const buf: pointer; len: csize_t; flags: cint): cint; cdecl; external LIB_ZMQ;
function zmq_recv(s: pointer; buf: pointer; len: csize_t; flags: cint): cint; cdecl; external LIB_ZMQ;
function zmq_socket_monitor(s: pointer; const addr: pchar; events: cint): cint; cdecl; external LIB_ZMQ;


(******************************************************************************)
(*  I/O multiplexing.                                                         *)
(******************************************************************************)
const
  ZMQ_POLLIN = 1;
  ZMQ_POLLOUT = 2;
  ZMQ_POLLERR = 4;
  ZMQ_POLLPRI = 8;

type
  Pzmq_pollitem_t = ^zmq_pollitem_t;
  zmq_pollitem_t = record
    socket: pointer;
{$ifdef MSWINDOWS}
    fd: TSocket;
{$else}
    fd: cint;
{$endif}
    events: cshort ;
    revents: cshort;
  end;

const
  ZMQ_POLLITEMS_DFLT = 16;

function zmq_poll(items: Pzmq_pollitem_t; nitems: cint; timeout: clong): cint; cdecl; external LIB_ZMQ;

(******************************************************************************)
(*  Message proxying                                                          *)
(******************************************************************************)

function zmq_proxy(frontend: pointer; backend: pointer; capture: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_proxy_steerable(frontend: pointer; backend: pointer; capture: pointer; control: pointer): cint; cdecl; external LIB_ZMQ;

(******************************************************************************)
(*  Probe library capabilities                                                *)
(******************************************************************************)

const
  ZMQ_HAS_CAPABILITIES = 1;

function zmq_has(const capability: pchar): cint; cdecl; external LIB_ZMQ;

const
(*  Deprecated aliases *)
  ZMQ_STREAMER = 1 deprecated;
  ZMQ_FORWARDER = 2 deprecated;
  ZMQ_QUEUE = 3 deprecated;

(*  Deprecated methods *)
function zmq_device(type_: cint; frontend: pointer; backend: pointer): cint; cdecl; external LIB_ZMQ; deprecated;
function zmq_sendmsg(s: pointer; msg: Pzmq_msg_t; flags: cint): cint; cdecl; external LIB_ZMQ; deprecated;
function zmq_recvmsg(s: pointer; msg: Pzmq_msg_t; flags: cint): cint; cdecl; external LIB_ZMQ; deprecated;

type
  Piovec = ^iovec;
  iovec = record
  end;
  
function zmq_sendiov (s: pointer; iov: Piovec; count: csize_t; flags: cint): cint; cdecl; external LIB_ZMQ; deprecated;
function zmq_recviov (s: pointer; iov: Piovec; count: pcsize_t; flags: cint): cint; cdecl; external LIB_ZMQ; deprecated;

(******************************************************************************)
(*  Encryption functions                                                      *)
(******************************************************************************)

(*  Encode data with Z85 encoding. Returns encoded data                       *)
function zmq_z85_encode(dest: pchar; const data: pcuint8; size: csize_t): pchar; cdecl; external LIB_ZMQ;

(*  Decode data with Z85 encoding. Returns decoded data                       *)
function zmq_z85_decode(dest: pcuint8; const string_: pchar): pcuint8; cdecl; external LIB_ZMQ;

(*  Generate z85-encoded public and private keypair with tweetnacl/libsodium. *)
(*  Returns 0 on success.                                                     *)
function zmq_curve_keypair(z85_public_key: pchar; z85_secret_key: pchar): cint; cdecl; external LIB_ZMQ;

(*  Derive the z85-encoded public key from the z85-encoded secret key.        *)
(*  Returns 0 on success.                                                     *)
function zmq_curve_public (z85_public_key: pcchar; const z85_secret_key: pcchar): cint; cdecl; external LIB_ZMQ;

(******************************************************************************)
(*  Atomic utility methods                                                    *)
(******************************************************************************)

function zmq_atomic_counter_new(): pointer; cdecl; external LIB_ZMQ;
procedure zmq_atomic_counter_set(counter: pointer; value: cint); cdecl; external LIB_ZMQ;
function zmq_atomic_counter_inc(counter: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_atomic_counter_dec(counter: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_atomic_counter_value(counter: pointer): cint; cdecl; external LIB_ZMQ;
procedure zmq_atomic_counter_destroy (counter_p: pointer); cdecl; external LIB_ZMQ;


(******************************************************************************)
(*  These functions are not documented by man pages -- use at your own risk.  *)
(*  If you need these to be part of the formal ZMQ API, then (a) write a man  *)
(*  page, and (b) write a test case in tests.                                 *)
(******************************************************************************)

(*  Helper functions are used by perf tests so that they don't have to care   *)
(*  about minutiae of time-related functions on different OS platforms.       *)

(*  Starts the stopwatch. Returns the handle to the watch.                    *)
function zmq_stopwatch_start(): pointer; cdecl; external LIB_ZMQ;

(*  Stops the stopwatch. Returns the number of microseconds elapsed since     *)
(*  the stopwatch was started.                                                *)
function zmq_stopwatch_stop(watch_: pointer): culong; cdecl; external LIB_ZMQ;

(*  Sleeps for specified number of seconds.                                   *)
procedure zmq_sleep(seconds_: cint); cdecl; external LIB_ZMQ;

type
  Pzmq_thread_fn = ^zmq_thread_fn;
  zmq_thread_fn = procedure(data: pointer); cdecl;

(* Start a thread. Returns a handle to the thread.                            *)
function zmq_threadstart(func: Pzmq_thread_fn; arg: pointer): pointer; cdecl; external LIB_ZMQ;

(* Wait for thread to complete then free up resources.                        *)
procedure zmq_threadclose(thread: pointer); cdecl; external LIB_ZMQ;


(******************************************************************************)
(*  These functions are DRAFT and disabled in stable releases, and subject to *)
(*  change at ANY time until declared stable.                                 *)
(******************************************************************************)

{$ifdef ZMQ_BUILD_DRAFT_API}

const
(*  DRAFT Socket types.                                                       *)
  ZMQ_SERVER = 12;
  ZMQ_CLIENT = 13;
  ZMQ_RADIO = 14;
  ZMQ_DISH = 15;
  ZMQ_GATHER = 16;
  ZMQ_SCATTER = 17;
  ZMQ_DGRAM = 18;

(*  DRAFT 0MQ socket events and monitoring                                    *)
  ZMQ_EVENT_HANDSHAKE_FAILED = $0800;
  ZMQ_EVENT_HANDSHAKE_SUCCEED = $1000;

(*  DRAFT Context options                                                     *)
  ZMQ_MSG_T_SIZE = 6;

(*  DRAFT Socket methods.                                                     *)
function zmq_join(s: pointer; const group: pcchar): cint; cdecl; external LIB_ZMQ;
function zmq_leave(s: pointer; const group: pcchar): cint; cdecl; external LIB_ZMQ;

(*  DRAFT Msg methods.                                                        *)
function zmq_msg_set_routing_id(msg: Pzmq_msg_t; routing_id: cuint32): cint; cdecl; external LIB_ZMQ;
function zmq_msg_routing_id(msg: Pzmq_msg_t): cuint32; cdecl; external LIB_ZMQ;
function zmq_msg_set_group(msg: Pzmq_msg_t; const group: pcchar): cint; cdecl; external LIB_ZMQ;
function zmq_msg_group(msg: Pzmq_msg_t): pcchar; cdecl; external LIB_ZMQ;

(******************************************************************************)
(*  Poller polling on sockets,fd and thread-safe sockets                      *)
(******************************************************************************)

{$define ZMQ_HAVE_POLLER}

type
  Pzmq_poller_event_t = ^zmq_poller_event_t;
  zmq_poller_event_t = record
    socket: pointer;
{$ifdef MSWINDOWS}
    fd: TSocket;
{$else}
    fd: cint;
{$endif}
    user_data: pointer;
    events: cshort;
  end;

function zmq_poller_new(): pointer; cdecl; external LIB_ZMQ;
function zmq_poller_destroy(poller_p: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_poller_add(poller: pointer; socket: pointer; user_data: pointer; events: cshort): cint; cdecl; external LIB_ZMQ;
function zmq_poller_modify(poller: pointer; socket: pointer; events: cshort): cint; cdecl; external LIB_ZMQ;
function zmq_poller_remove(poller: pointer; socket: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_poller_wait(poller: pointer; event: Pzmq_poller_event_t; timeout: clong): cint; cdecl; external LIB_ZMQ;
function zmq_poller_wait_all(poller: pointer; events: Pzmq_poller_event_t; n_events: cint; timeout: clong): cint; cdecl; external LIB_ZMQ;

{$ifdef MSWINDOWS}
function zmq_poller_add_fd(poller: pointer; fd: TSocket; user_data: pointer; events: cshort): cint; cdecl; external LIB_ZMQ;
function zmq_poller_modify_fd(poller: pointer; fd: TSocket; events: cshort): cint; cdecl; external LIB_ZMQ;
function zmq_poller_remove_fd(poller: pointer; fd: TSocket): cint; cdecl; external LIB_ZMQ;
{$else}
function zmq_poller_add_fd(poller: pointer; fd: cint; user_data: pointer; events: short): cint; cdecl; external LIB_ZMQ;
function zmq_poller_modify_fd(poller: pointer; fd: cint; events: cshort): cint; cdecl; external LIB_ZMQ;
function zmq_poller_remove_fd(poller: pointer; fd: cint): cint; cdecl; external LIB_ZMQ;
{$endif}

(******************************************************************************)
(*  Scheduling timers                                                         *)
(******************************************************************************)

{$define ZMQ_HAVE_TIMERS}

type
  zmq_timer_fn = procedure (timer_id: cint; arg: pointer); cdecl;

function zmq_timers_new(): pointer; cdecl; external LIB_ZMQ;
function zmq_timers_destroy (timers_p: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_timers_add (timers: pointer; interval: csize_t; handler: zmq_timer_fn; arg: pointer): cint; cdecl; external LIB_ZMQ;
function zmq_timers_cancel (timers: pointer; timer_id: cint): cint; cdecl; external LIB_ZMQ;
function zmq_timers_set_interval (timers: pointer; timer_id: cint; interval: csize_t): cint; cdecl; external LIB_ZMQ;
function zmq_timers_reset (timers: pointer; timer_id: cint): cint; cdecl; external LIB_ZMQ;
function zmq_timers_timeout (timers: pointer): clong; cdecl; external LIB_ZMQ;
function zmq_timers_execute (timers: pointer): cint; cdecl; external LIB_ZMQ;

{$endif} // ZMQ_BUILD_DRAFT_API


// #undef ZMQ_EXPORT

// #ifdef __cplusplus
// }
// #endif

// #endif

implementation


end.

