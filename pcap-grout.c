/*
 * Copyright (c) 2026 Vincent Jardin, Free Mobile, Iliad
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * pcap-grout: libpcap capture module for grout (Graph Router).
 *
 * Connects to grout's UNIX API socket, sends CAPTURE_START to create
 * a shared memory ring, then reads raw packets directly from the mmap'd
 * ring. No DPDK dependency — uses only grout's public C API headers.
 *
 * Device names use the "grout:" prefix followed by the interface name:
 *   tcpdump -i grout:p0
 *   tcpdump -i grout:all
 *
 * The grout daemon must be running and the API socket must be accessible
 * (default: /run/grout.sock, override via GROUT_SOCK_PATH env var).
 */

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "pcap-int.h"
#include "pcap-grout.h"

/*
 * grout's public API headers are written in C23 (gnu2x). Two headers
 * are safe to include from C11/C17 code:
 *
 *  - gr_api_client_impl.h (and gr_api.h): uses STREAM_RESP() which
 *    expands to static_assert(alignof(...)). This works in C11 if
 *    <stdalign.h> is included first (provides the alignof macro).
 *
 *  - gr_capture_ring.h: pure C11 stdatomic.h, no C23 features.
 *
 * We do NOT include gr_infra.h because it uses C23 enum underlying
 * types ("typedef enum : uint16_t") and the BASE() macro which
 * requires GCC's -fms-extensions for anonymous unions. Instead, the
 * minimal API constants and request structs are defined locally below.
 */
#include <stdalign.h>
#include <gr_api_client_impl.h>
#include <gr_capture_ring.h>

/*
 * Minimal grout API constants and types needed for capture.
 * Avoids including gr_infra.h which requires C23 + -fms-extensions.
 */
#define GR_INFRA_MODULE		0xacdc
#define GR_IFACE_ID_UNDEF	0

#define GR_INFRA_IFACE_GET	((uint32_t)(0xffff & GR_INFRA_MODULE) << 16 | 0x0003)
#define GR_INFRA_IFACE_LIST	((uint32_t)(0xffff & GR_INFRA_MODULE) << 16 | 0x0004)
#define GR_INFRA_CAPTURE_START	((uint32_t)(0xffff & GR_INFRA_MODULE) << 16 | 0x0080)
#define GR_INFRA_CAPTURE_STOP	((uint32_t)(0xffff & GR_INFRA_MODULE) << 16 | 0x0081)

#define GR_IFACE_TYPE_PORT	2

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct grout_iface_get_req {
	uint16_t iface_id;
	char name[IFNAMSIZ];
};

struct grout_iface_get_resp {
	uint16_t id;
	/* remaining fields omitted — we only need the id */
};

struct grout_iface_list_req {
	uint8_t type;
};

/* Minimal iface response: first two bytes are the id, then type, then mode,
 * then flags, then state, then mtu, then vrf_id, then domain_id, then speed,
 * then name. We parse just enough to extract id and name. */
struct grout_iface_resp {
	uint16_t id;
	uint8_t type;
	uint8_t mode;
	uint16_t flags;
	uint16_t state;
	uint16_t mtu;
	uint16_t vrf_id;
	uint16_t domain_id;
	uint32_t speed;
	char name[IFNAMSIZ];
	/* rest omitted */
};

struct grout_capture_start_req {
	uint16_t iface_id;
	uint16_t _pad;
	uint32_t snap_len;
};

#define GR_CAPTURE_SHM_PATH_SIZE 108

struct grout_capture_start_resp {
	char shm_path[GR_CAPTURE_SHM_PATH_SIZE];
};

#define GROUT_PREFIX		"grout:"
#define GROUT_PREFIX_LEN	6
#define GROUT_DEF_SOCK_PATH	"/run/grout.sock"
#define GROUT_POLL_US		100

struct pcap_grout {
	struct gr_api_client *client;
	struct gr_capture_ring *ring;
	size_t ring_size;
	int nonblock;
	uint64_t pkt_recv;
	uint64_t pkt_drop;
	struct timeval required_select_timeout;
};

static void
pcap_grout_close(pcap_t *p)
{
	struct pcap_grout *pg = p->priv;

	if (pg->client) {
		gr_api_client_send_recv(pg->client, GR_INFRA_CAPTURE_STOP,
		    0, NULL, NULL);
		gr_api_client_disconnect(pg->client);
		pg->client = NULL;
	}
	if (pg->ring != NULL && pg->ring != MAP_FAILED) {
		munmap(pg->ring, pg->ring_size);
		pg->ring = NULL;
	}
	pcapint_cleanup_live_common(p);
}

static inline void
grout_ts_to_timeval(const struct gr_capture_ring *ring,
    const struct gr_capture_slot *slot, struct timeval *tv)
{
	uint64_t ns = gr_capture_slot_timestamp_ns(ring, slot);
	tv->tv_sec = (time_t)(ns / 1000000000ULL);
	tv->tv_usec = (suseconds_t)((ns % 1000000000ULL) / 1000);
}

static int
pcap_grout_dispatch(pcap_t *p, int max_cnt, pcap_handler cb, u_char *cb_arg)
{
	struct pcap_grout *pg = p->priv;
	struct pcap_pkthdr hdr;
	int pkt_cnt = 0;
	int timeout_ms = p->opt.timeout;
	int waited_ms = 0;

	if (PACKET_COUNT_IS_UNLIMITED(max_cnt))
		max_cnt = INT_MAX;

	while (pkt_cnt < max_cnt) {
		if (p->break_loop) {
			p->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}

		const struct gr_capture_slot *slot =
		    gr_capture_ring_dequeue(pg->ring);

		if (slot == NULL) {
			if (pg->nonblock)
				break;
			if (timeout_ms > 0 && waited_ms >= timeout_ms)
				break;
			usleep(GROUT_POLL_US);
			waited_ms++;
			continue;
		}

		waited_ms = 0;
		pg->pkt_recv++;

		uint32_t caplen = slot->cap_len;
		if (caplen > (uint32_t)p->snapshot)
			caplen = (uint32_t)p->snapshot;

		grout_ts_to_timeval(pg->ring, slot, &hdr.ts);
		hdr.caplen = caplen;
		hdr.len = slot->pkt_len;

		if (p->fcode.bf_insns == NULL ||
		    pcapint_filter(p->fcode.bf_insns, slot->data,
		    slot->pkt_len, caplen)) {
			cb(cb_arg, &hdr, slot->data);
			pkt_cnt++;
		} else {
			pg->pkt_drop++;
		}
	}

	return pkt_cnt;
}

static int
pcap_grout_inject(pcap_t *p, const void *buf _U_, int size _U_)
{
	pcapint_strlcpy(p->errbuf, "grout: packet injection not supported",
	    PCAP_ERRBUF_SIZE);
	return PCAP_ERROR;
}

static int
pcap_grout_stats(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_grout *pg = p->priv;

	if (ps == NULL)
		return 0;
	ps->ps_recv = (u_int)pg->pkt_recv;
	ps->ps_drop = (u_int)pg->pkt_drop;
	ps->ps_ifdrop = 0;
	return 0;
}

static int
pcap_grout_setnonblock(pcap_t *p, int nonblock)
{
	struct pcap_grout *pg = p->priv;
	pg->nonblock = nonblock;
	return 0;
}

static int
pcap_grout_getnonblock(pcap_t *p)
{
	struct pcap_grout *pg = p->priv;
	return pg->nonblock;
}

/*
 * Resolve an interface name to a grout iface_id.
 * "all" returns GR_IFACE_ID_UNDEF (capture all ports).
 */
static int
grout_resolve_iface(struct gr_api_client *client, const char *name,
    uint16_t *iface_id, char *errbuf)
{
	if (strcmp(name, "all") == 0) {
		*iface_id = GR_IFACE_ID_UNDEF;
		return 0;
	}

	struct grout_iface_get_req req;
	void *resp = NULL;

	memset(&req, 0, sizeof(req));
	req.iface_id = 0;
	snprintf(req.name, sizeof(req.name), "%s", name);

	if (gr_api_client_send_recv(client, GR_INFRA_IFACE_GET,
	    sizeof(req), &req, &resp) < 0) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "grout: interface '%s' not found: %s",
		    name, strerror(errno));
		return -1;
	}

	struct grout_iface_get_resp *r = resp;
	*iface_id = r->id;
	free(resp);
	return 0;
}

static int
pcap_grout_activate(pcap_t *p)
{
	struct pcap_grout *pg = p->priv;
	const char *sock_path;
	const char *ifname;
	uint16_t iface_id;
	int ret = PCAP_ERROR;

	ifname = p->opt.device + GROUT_PREFIX_LEN;
	if (*ifname == '\0') {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "grout: empty interface name");
		return PCAP_ERROR_NO_SUCH_DEVICE;
	}

	sock_path = getenv("GROUT_SOCK_PATH");
	if (sock_path == NULL)
		sock_path = GROUT_DEF_SOCK_PATH;

	pg->client = gr_api_client_connect(sock_path);
	if (pg->client == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "grout: cannot connect to %s: %s",
		    sock_path, strerror(errno));
		return PCAP_ERROR;
	}

	if (grout_resolve_iface(pg->client, ifname, &iface_id,
	    p->errbuf) < 0) {
		ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto fail;
	}

	struct grout_capture_start_req creq;
	memset(&creq, 0, sizeof(creq));
	creq.iface_id = iface_id;
	creq.snap_len = (uint32_t)p->snapshot;

	void *resp = NULL;
	if (gr_api_client_send_recv(pg->client, GR_INFRA_CAPTURE_START,
	    sizeof(creq), &creq, &resp) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "grout: capture start failed: %s", strerror(errno));
		goto fail;
	}

	struct grout_capture_start_resp *cresp = resp;
	char shm_path[GR_CAPTURE_SHM_PATH_SIZE];
	memset(shm_path, 0, sizeof(shm_path));
	memcpy(shm_path, cresp->shm_path, sizeof(cresp->shm_path));
	free(resp);

	int shm_fd = shm_open(shm_path, O_RDWR, 0);
	if (shm_fd < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "grout: shm_open(%s): %s", shm_path, strerror(errno));
		goto fail;
	}
	struct stat st;
	if (fstat(shm_fd, &st) < 0) {
		close(shm_fd);
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "grout: fstat: %s", strerror(errno));
		goto fail;
	}
	pg->ring_size = st.st_size;
	pg->ring = mmap(NULL, pg->ring_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, shm_fd, 0);
	close(shm_fd);
	if (pg->ring == MAP_FAILED) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "grout: mmap: %s", strerror(errno));
		pg->ring = NULL;
		goto fail;
	}

	if (pg->ring->magic != GR_CAPTURE_RING_MAGIC) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "grout: invalid capture ring magic");
		goto fail;
	}

	p->linktype = DLT_EN10MB;
	if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
		p->snapshot = MAXIMUM_SNAPLEN;

	p->read_op = pcap_grout_dispatch;
	p->inject_op = pcap_grout_inject;
	p->setfilter_op = pcapint_install_bpf_program;
	p->setdirection_op = NULL;
	p->set_datalink_op = NULL;
	p->getnonblock_op = pcap_grout_getnonblock;
	p->setnonblock_op = pcap_grout_setnonblock;
	p->stats_op = pcap_grout_stats;
	p->cleanup_op = pcap_grout_close;
	p->breakloop_op = pcapint_breakloop_common;

	pg->required_select_timeout.tv_sec = 0;
	pg->required_select_timeout.tv_usec = GROUT_POLL_US;
	p->required_select_timeout = &pg->required_select_timeout;

	return 0;

fail:
	pcap_grout_close(p);
	return ret;
}

pcap_t *
pcap_grout_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p;

	*is_ours = (strncmp(device, GROUT_PREFIX, GROUT_PREFIX_LEN) == 0);
	if (!*is_ours)
		return NULL;

	p = PCAP_CREATE_COMMON(ebuf, struct pcap_grout);
	if (p == NULL)
		return NULL;

	p->activate_op = pcap_grout_activate;
	return p;
}

int
pcap_grout_findalldevs(pcap_if_list_t *devlistp, char *ebuf)
{
	const char *sock_path;
	struct gr_api_client *client;

	sock_path = getenv("GROUT_SOCK_PATH");
	if (sock_path == NULL)
		sock_path = GROUT_DEF_SOCK_PATH;

	client = gr_api_client_connect(sock_path);
	if (client == NULL)
		return 0; /* grout not running, no devices to report */

	struct grout_iface_list_req req;
	memset(&req, 0, sizeof(req));
	req.type = GR_IFACE_TYPE_PORT;

	const struct grout_iface_resp *iface;
	int ret;
	char devname[64];
	char desc[128];

	gr_api_client_stream_foreach(
	    iface, ret, client, GR_INFRA_IFACE_LIST, sizeof(req), &req
	) {
		snprintf(devname, sizeof(devname), "%s%s",
		    GROUT_PREFIX, iface->name);
		snprintf(desc, sizeof(desc), "grout interface %s (id=%u)",
		    iface->name, iface->id);
		if (pcapint_add_dev(devlistp, devname, 0, desc, ebuf)
		    == NULL) {
			ret = PCAP_ERROR;
			break;
		}
	}

	if (ret >= 0) {
		if (pcapint_add_dev(devlistp, "grout:all", 0,
		    "grout: capture on all port interfaces", ebuf) == NULL)
			ret = PCAP_ERROR;
	}

	gr_api_client_disconnect(client);
	return (ret < 0) ? ret : 0;
}
