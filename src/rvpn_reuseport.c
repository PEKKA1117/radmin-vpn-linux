/* rvpn_reuseport.c — LD_PRELOAD shim for wineserver: set SO_REUSEPORT on every
 * TCP socket at creation, so that Windows SO_REUSEADDR semantics actually hold.
 *
 * Issue #24, Radmin VPN 2.1. 2.1 added TCP port-reuse NAT traversal (new classes
 * CTcpListenerNotificator, CTcpNatInfoCollector, CMsgTcpNatInfo, new export
 * UESC_GetTcpNatType): the service binds a listener to uplink:PORT, advertises
 * that mapping to the server, then binds its *outbound* peer sockets to the SAME
 * local port so the connect leaves through the NAT mapping the peer was told
 * about. Every one of those sockets sets SO_REUSEADDR first, which is the
 * sanctioned Windows way to share a local port — MSDN "Using SO_REUSEADDR and
 * SO_EXCLUSIVEADDRUSE", Server 2003 and later, same user account: first bind
 * SO_REUSEADDR/specific + second bind SO_REUSEADDR/specific = Success.
 *
 * Under Wine every one of those binds fails with WSAEACCES (10013), the peer
 * connect aborts before any transport exists, and the GUI shows peers spinning
 * forever. 2.0 did not do this, which is why downgrading works.
 *
 * Mechanism, in wine/server/sock.c:
 *   - socket creation sets Unix SO_REUSEADDR=1 unconditionally for TCP, which is
 *     enough for two *idle* bound sockets to share a port;
 *   - the application's SO_REUSEADDR sets no Unix option at all for TCP —
 *
 *         if (is_tcp_socket( sock )) ret = 0;
 *         else ret = setsockopt( unix_fd, SOL_SOCKET, SO_REUSEADDR, ... );
 *     #ifdef __APPLE__
 *         if (!ret) ret = setsockopt( unix_fd, SOL_SOCKET, SO_REUSEPORT, ... );
 *     #endif
 *
 *     Winsock's reuse rules are emulated purely in wineserver's
 *     bound_addresses_tree, and SO_REUSEPORT is compiled __APPLE__-only;
 *   - Linux lets sockets share a local port with a LISTENING one only when
 *     SO_REUSEPORT is set on all of them. So the second bind takes the kernel's
 *     EADDRINUSE, which wineserver then relabels to EACCES because the socket
 *     had reuseaddr set. The WSAEACCES is a kernel refusal wearing a Windows
 *     error code, not wineserver's own conflict check.
 *
 * The trigger is listen(), not SO_REUSEADDR: with the first socket merely bound
 * the second bind succeeds even on stock Wine.
 *
 * Why here and not in adapter_hook.dll: the Unix file descriptors belong to
 * wineserver (server/sock.c init_socket calls socket()), so no in-process PE hook
 * can reach them. run.sh therefore preloads this into an explicit wineserver boot
 * rather than into the service launch.
 *
 * What this does NOT do: wineserver's own bookkeeping still runs first and still
 * refuses the binds Windows refuses. Verified against a four-case repro — a
 * second bind *without* SO_REUSEADDR onto a listening socket's port still gets
 * WSAEADDRINUSE with this loaded. We remove the kernel-level obstruction, not the
 * Windows conflict rules; this is not a port-hijacking hole.
 *
 * Scope: one wineprefix's wineserver, for this user, for the life of the process.
 * It touches no system file.
 *
 * CBA: blanket on all TCP sockets. Per-socket gating is impossible from out here
 * precisely because Wine never tells the Unix layer that the app asked for
 * SO_REUSEADDR — there is no signal to key on. The real fix is ~3 lines in
 * server/sock.c plumbing that request down to a Unix SO_REUSEPORT on Linux, which
 * would make this shim unnecessary; reported upstream with a minimal repro.
 *
 * Unlike rvpn_dnsfix.so this needs no multilib thought: wineserver is always the
 * host architecture, whatever wow64 flavour the Wine build uses.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

static int (*real_socket)(int, int, int);

int socket(int domain, int type, int protocol)
{
    if (!real_socket) {
        real_socket = dlsym(RTLD_NEXT, "socket");
        if (!real_socket) { errno = ENOSYS; return -1; }
    }

    int fd = real_socket(domain, type, protocol);
    if (fd < 0)
        return fd;

    /* SOCK_NONBLOCK/SOCK_CLOEXEC ride in the high bits of `type`. */
    int base = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if ((domain == AF_INET || domain == AF_INET6) && base == SOCK_STREAM &&
        (protocol == 0 || protocol == IPPROTO_TCP)) {
        /* Must be set before bind(). Failure is not fatal — without it we are
         * simply back to stock Wine behaviour — so never disturb errno or the
         * returned fd on account of it. */
        int on = 1, saved = errno;
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
        errno = saved;
    }
    return fd;
}
