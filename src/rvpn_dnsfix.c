/* rvpn_dnsfix.c — LD_PRELOAD shim that short-circuits reverse DNS of private
 * addresses at the glibc layer, for the Wine process that runs Radmin's service.
 *
 * Issue #16. Radmin's ROL connector reverse-resolves every local candidate
 * address it gathers (e.g. docker0's 172.17.0.1) with a PTR lookup. On a host
 * whose resolver black-holes RFC1918 PTR queries — systemd-resolved forwarding
 * upstream where nothing ever answers — each lookup blocks ~5s and is retried
 * across every nameserver, well past Radmin's ready deadline: the service
 * registers and then never reports "ready".
 *
 * Why here and not in adapter_hook.dll: on the affected hosts the call is issued
 * by Wine's *Unix* side (ws2_32.so -> glibc getnameinfo), so no in-process PE
 * hook can see it. The reporter (ayozetr, who diagnosed this end to end and
 * wrote the original of this shim) verified that exhaustively: hooking
 * getnameinfo's IAT in every loaded module, its ws2_32 export table, and its
 * entry point with an inline detour all install correctly and never fire for
 * 172.17.0.1. rc9's GetProcAddress/GetNameInfoW interception fires on some hosts
 * and not on others; interposing glibc catches every path by construction,
 * because on wow64 all Win32 reverse-resolution entry points bottom out in these
 * two symbols.
 *
 * Public addresses fall through to the real libc function untouched. Private
 * ones get their numeric form back immediately — Radmin only ever uses these
 * numerically, so it is lossless.
 *
 * Scope: run.sh LD_PRELOADs this into the service launch only. It touches no
 * system file and dies with the process.
 *
 * CBA: built 64-bit only. The AppImage bundles staging-amd64-wow64, whose Unix
 * side is x86_64, so this is the right class there. On a system Wine built as
 * old-wow64 (32-bit Unix side for 32-bit PEs) the loader refuses the preload
 * with a warning on stderr and everything keeps working — minus this fix.
 * Multilib would be the upgrade path if that ever shows up in a report.
 */
#define _GNU_SOURCE
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* host-order IPv4 range test — same set as adapter_hook.c's is_private_v4 */
static int dnsfix_is_private_v4(uint32_t h)
{
    if ((h & 0xFF000000u) == 0x7F000000u) return 1;   /* 127.0.0.0/8   loopback */
    if ((h & 0xFF000000u) == 0x0A000000u) return 1;   /* 10.0.0.0/8             */
    if ((h & 0xFFF00000u) == 0xAC100000u) return 1;   /* 172.16.0.0/12          */
    if ((h & 0xFFFF0000u) == 0xC0A80000u) return 1;   /* 192.168.0.0/16         */
    if ((h & 0xFFFF0000u) == 0xA9FE0000u) return 1;   /* 169.254.0.0/16  APIPA  */
    if ((h & 0xFFC00000u) == 0x64400000u) return 1;   /* 100.64.0.0/10   CGNAT  */
    return 0;
}

/* Same idea for v6: loopback, link-local and ULA (which covers Radmin's own
 * fdfd::/16 VPN addresses). Every interface carries an fe80:: address, so a
 * resolver that black-holes private PTR stalls on those exactly the same way. */
static int dnsfix_is_private_v6(const struct in6_addr *a)
{
    if (IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_LINKLOCAL(a) ||
        IN6_IS_ADDR_SITELOCAL(a))
        return 1;
    if ((a->s6_addr[0] & 0xFE) == 0xFC) return 1;     /* fc00::/7  ULA */
    return 0;
}

int getnameinfo(const struct sockaddr *sa, socklen_t salen,
                char *host, socklen_t hostlen,
                char *serv, socklen_t servlen, int flags)
{
    char numeric[INET6_ADDRSTRLEN + IF_NAMESIZE + 2];
    uint16_t port = 0;
    int hit = 0;

    numeric[0] = '\0';

    if (sa && sa->sa_family == AF_INET &&
        salen >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
        if (dnsfix_is_private_v4(ntohl(si->sin_addr.s_addr))) {
            inet_ntop(AF_INET, &si->sin_addr, numeric, sizeof(numeric));
            port = ntohs(si->sin_port);
            hit = 1;
        }
    } else if (sa && sa->sa_family == AF_INET6 &&
               salen >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *si6 = (const struct sockaddr_in6 *)sa;
        if (dnsfix_is_private_v6(&si6->sin6_addr)) {
            inet_ntop(AF_INET6, &si6->sin6_addr, numeric, sizeof(numeric));
            if (si6->sin6_scope_id) {
                char ifn[IF_NAMESIZE];
                size_t n = strlen(numeric);
                if (if_indextoname(si6->sin6_scope_id, ifn))
                    snprintf(numeric + n, sizeof(numeric) - n, "%%%s", ifn);
                else
                    snprintf(numeric + n, sizeof(numeric) - n, "%%%u",
                             (unsigned)si6->sin6_scope_id);
            }
            port = ntohs(si6->sin6_port);
            hit = 1;
        }
    }

    if (hit) {
        /* CBA: we answer the numeric form even under NI_NAMEREQD, where the
         * strictly correct reply is EAI_NONAME. This is the shape that was
         * verified on the reporter's host (ready in 17.7s, zero PTR on the
         * wire) and Radmin consumes the string numerically either way — not
         * worth trading a field-validated behaviour for spec purity. */
        if (host && hostlen) {
            if (strlen(numeric) >= (size_t)hostlen)
                return EAI_OVERFLOW;
            strcpy(host, numeric);
        }
        if (serv && servlen) {
            char sbuf[8];
            snprintf(sbuf, sizeof(sbuf), "%u", (unsigned)port);
            if (strlen(sbuf) >= (size_t)servlen)
                return EAI_OVERFLOW;
            strcpy(serv, sbuf);
        }
        return 0;
    }

    static int (*real)(const struct sockaddr *, socklen_t, char *, socklen_t,
                       char *, socklen_t, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "getnameinfo");
    return real ? real(sa, salen, host, hostlen, serv, servlen, flags) : EAI_FAIL;
}

/* Same short-circuit for the classic reverse resolver, in case any path uses it. */
struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type)
{
    if (addr && type == AF_INET && len == 4) {
        uint32_t net;
        memcpy(&net, addr, 4);
        if (dnsfix_is_private_v4(ntohl(net))) {
            h_errno = HOST_NOT_FOUND;
            return NULL;
        }
    } else if (addr && type == AF_INET6 && len == (socklen_t)sizeof(struct in6_addr)) {
        if (dnsfix_is_private_v6((const struct in6_addr *)addr)) {
            h_errno = HOST_NOT_FOUND;
            return NULL;
        }
    }
    static struct hostent *(*real)(const void *, socklen_t, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "gethostbyaddr");
    return real ? real(addr, len, type) : NULL;
}
