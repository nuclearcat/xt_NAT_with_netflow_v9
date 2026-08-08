/*
 * cps-gen.c - minimal UDP flood for measuring xt_CGNAT session setup rate.
 *
 * Every distinct (source address, source port) pair is one new NAT session, so
 * driving a stream of unique pairs at the subscriber side of the test topology
 * and watching "Created NAT sessions" gives connections per second.
 *
 * AF_PACKET + sendmmsg() deliberately: it hands complete frames to the device
 * and skips the local routing and socket paths entirely, so what is being
 * measured is the NAT, not this program's egress. It is still only a ballpark
 * inside a VM - veth and a virtual CPU are not a NIC.
 *
 *   cps-gen <ifname> <dst-mac> <src-ip-base> <n-src-ips> <dst-ip> <seconds>
 *           [ports-per-ip]
 *
 * Source addresses run from src-ip-base for n-src-ips consecutive addresses,
 * source ports cycle 1024..65535. Prints "sent <packets> in <sec>".
 *
 * ports-per-ip bounds the port range, and with it the whole tuple space, to
 * n-src-ips * ports-per-ip. Once that many sessions exist the generator is
 * replaying traffic over established ones instead of creating new ones, which
 * is the only way to measure forwarding rather than session setup - and
 * forwarding is what a NAT spends nearly all of its time doing. 0 means the
 * full range, i.e. keep creating.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BATCH  64
#define FRAME  60                 /* 14 eth + 20 ip + 8 udp + 18 pad */
#define PORT_LO 1024
#define PORT_HI 65535

struct iphdr_ {
	unsigned char  ihl_version, tos;
	unsigned short tot_len, id, frag_off;
	unsigned char  ttl, protocol;
	unsigned short check;
	unsigned int   saddr, daddr;
} __attribute__((packed));

struct udphdr_ {
	unsigned short source, dest, len, check;
} __attribute__((packed));

static unsigned short csum16(const void *buf, int len)
{
	const unsigned char *p = buf;
	unsigned long sum = 0;
	int i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (p[i] << 8) | p[i + 1];
	if (i < len)
		sum += p[i] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (unsigned short)~sum;
}

static int parse_mac(const char *s, unsigned char *out)
{
	unsigned int m[6];
	int i;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x",
		   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
		return -1;
	for (i = 0; i < 6; i++)
		out[i] = (unsigned char)m[i];
	return 0;
}

static double now_sec(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	unsigned char frames[BATCH][FRAME], dmac[6], smac[6] = {0x02,0,0,0,0,1};
	struct mmsghdr msgs[BATCH];
	struct iovec iov[BATCH];
	struct sockaddr_ll sll;
	unsigned int base_ip, dst_ip, n_ips, port = PORT_LO, ip_off = 0;
	unsigned int port_hi = PORT_HI, per_ip = 0;
	unsigned long long sent = 0;
	double deadline, start;
	int fd, ifindex, i, seconds;

	if (argc != 7 && argc != 8) {
		fprintf(stderr,
			"usage: %s <ifname> <dst-mac> <src-ip-base> <n-src-ips> <dst-ip> <seconds> [ports-per-ip]\n",
			argv[0]);
		return 2;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) { perror("if_nametoindex"); return 1; }
	if (parse_mac(argv[2], dmac)) { fprintf(stderr, "bad mac: %s\n", argv[2]); return 1; }

	base_ip = ntohl(inet_addr(argv[3]));
	n_ips   = (unsigned int)strtoul(argv[4], NULL, 10);
	dst_ip  = inet_addr(argv[5]);
	seconds = atoi(argv[6]);
	if (!n_ips) n_ips = 1;
	if (argc == 8) {
		per_ip = (unsigned int)strtoul(argv[7], NULL, 10);
		if (per_ip) {
			port_hi = PORT_LO + per_ip - 1;
			if (port_hi > PORT_HI) port_hi = PORT_HI;
		}
	}

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) { perror("socket(AF_PACKET)"); return 1; }

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex  = ifindex;
	sll.sll_halen    = 6;
	memcpy(sll.sll_addr, dmac, 6);
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind"); return 1;
	}

	/* frame template: everything except the addresses and ports is constant */
	memset(frames, 0, sizeof(frames));
	memset(msgs, 0, sizeof(msgs));
	for (i = 0; i < BATCH; i++) {
		unsigned char *f = frames[i];
		struct iphdr_ *ip = (struct iphdr_ *)(f + 14);
		struct udphdr_ *udp = (struct udphdr_ *)(f + 34);

		memcpy(f, dmac, 6);
		memcpy(f + 6, smac, 6);
		f[12] = 0x08; f[13] = 0x00;             /* ETH_P_IP */

		ip->ihl_version = 0x45;
		ip->tot_len  = htons(FRAME - 14);
		ip->ttl      = 64;
		ip->protocol = IPPROTO_UDP;
		ip->daddr    = dst_ip;

		udp->dest = htons(9);                   /* discard */
		udp->len  = htons(FRAME - 34);
		udp->check = 0;                         /* optional for IPv4 */

		iov[i].iov_base = f;
		iov[i].iov_len  = FRAME;
		msgs[i].msg_hdr.msg_iov    = &iov[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
	}

	start = now_sec();
	deadline = start + seconds;

	while (now_sec() < deadline) {
		int n;

		for (i = 0; i < BATCH; i++) {
			struct iphdr_ *ip = (struct iphdr_ *)(frames[i] + 14);
			struct udphdr_ *udp = (struct udphdr_ *)(frames[i] + 34);

			ip->saddr = htonl(base_ip + ip_off);
			ip->check = 0;
			ip->check = htons(csum16(ip, 20));
			udp->source = htons((unsigned short)port);

			/* Address is the fast-varying axis, port the slow one.
			 * The other way round exhausts one subscriber's 64512
			 * ports before touching the next, so it hits the 4096
			 * per-user cap after 4096 packets and then generates
			 * ~60k pure refusals per address - measuring the cap,
			 * not the session rate. This way every pass adds one
			 * session to each subscriber in turn.
			 */
			if (++ip_off >= n_ips) {
				ip_off = 0;
				if (++port > port_hi)
					port = PORT_LO;
			}
		}

		n = sendmmsg(fd, msgs, BATCH, 0);
		if (n < 0) {
			if (errno == ENOBUFS || errno == EAGAIN || errno == EINTR)
				continue;             /* queue full: that is the point */
			perror("sendmmsg");
			break;
		}
		sent += n;
	}

	printf("sent %llu in %.2f\n", sent, now_sec() - start);
	if (per_ip)
		printf("tuples %llu\n", (unsigned long long)n_ips * per_ip);
	close(fd);
	return 0;
}
