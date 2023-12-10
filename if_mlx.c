/*	$OpenBSD$	*/

/*
 * Copyright (c) 2016  Jonathan Matthew <jmatthew@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/device.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/atomic.h>

#include <machine/bus.h>
#include <machine/intr.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcidevs.h>

#include <dev/pci/mlxreg.h>

/* no idea if this is enough */
#define MLX_SPECIAL_QPS		8
#define MLX_ALLOC_QPS		8
#define MLX_ALLOC_CQS		8
#define MLX_ALLOC_EQS		8
#define MLX_ALLOC_MTTS		128
#define MLX_ALLOC_MPTS		8
#define MLX_ALLOC_MCS		8

#define MLX_ALLOC_UARS		1024

/* not sure how big these need to be */
#define MLX_ALLOC_EQES		0x200
#define MLX_ALLOC_CQES		8

/* these are probably way too small? */
#define MLX_ALLOC_TX_WQES	64
#define MLX_ALLOC_RX_WQES	64

#define MLX_MAX_PORTS		2

#define MLX_CQS_PER_PORT	2
#define MLX_DOORBELLS_PER_PORT	3
#define MLX_DOORBELL_STRIDE	128

enum {
	MLX_CQ_TX = 0,
	MLX_CQ_RX
};

#define MLX_QPS_PER_PORT	4

struct mlx_dmamem {
	bus_dmamap_t		mxm_map;
	bus_dma_segment_t	mxm_seg;
	int			mxm_nsegs;
	size_t			mxm_size;
	caddr_t			mxm_kva;
};
#define MLX_DMA_MAP(_mxm)	((_mxm)->mxm_map)
#define MLX_DMA_LEN(_mxm)	((_mxm)->mxm_size)
#define MLX_DMA_DVA(_mxm)	((_mxm)->mxm_map->dm_segs[0].ds_addr)
#define MLX_DMA_KVA(_mxm)	((_mxm)->mxm_kva)

struct mlx_icm_block {
	uint64_t		icm_addr;
	uint64_t		icm_len;
	struct mlx_dmamem	*icm_mem;
};
#define MLX_ICM_BLOCK_COUNT	20

struct mlx_mtt_range {
	uint64_t		mtt_addr;
	int			mtt_pages;
	int			mtt_num;
	int			mtt_page_offset;
};

struct mlxc_softc {
	struct device		sc_dev;

	pci_chipset_tag_t	sc_pc;
	pcitag_t		sc_tag;

	bus_dma_tag_t		sc_dmat;
	bus_space_tag_t		sc_memt_cfg;
	bus_space_handle_t	sc_memh_cfg;
	bus_size_t		sc_mems_cfg;
	bus_space_tag_t		sc_memt_uar;
	bus_space_handle_t	sc_memh_uar;
	bus_size_t		sc_mems_uar;
	void			*sc_ih;

	struct mlx_dmamem	*sc_mbox;
	struct mlx_dmamem	**sc_fw_areas;
	int			sc_cmd_toggle;

	bus_size_t		sc_clr_offset;
	uint64_t		sc_clr_int;

	struct mlx_query_dev_cap sc_dev_cap;

	struct mlx_icm_block	sc_icm[MLX_ICM_BLOCK_COUNT];
	int			sc_icm_blocks;
	struct mlx_dmamem	*sc_icm_aux;
	int			sc_qpcs;
	int			sc_srqs;
	int			sc_cqcs;
	int			sc_eqcs;
	int			sc_mtts;
	int			sc_mpts;
	int			sc_mcs;
	uint64_t		sc_qpc_addr;
	uint64_t		sc_altc_addr;
	uint64_t		sc_auxc_addr;
	uint64_t		sc_srqc_addr;
	uint64_t		sc_cqc_addr;
	uint64_t		sc_eqc_addr;
	uint64_t		sc_mtt_addr;
	uint64_t		sc_mpt_addr;
	uint64_t		sc_mcs_addr;

	bus_dmamap_t		sc_other_map;
	uint64_t		sc_mtt_offset;
	struct mlx_mtt		*sc_mtt_ptr;

	uint32_t		sc_pd;
	uint32_t		sc_mpt_key;
	uint32_t		sc_mpt;

	int			sc_next_mtt;
	int			sc_first_cq;
	int			sc_first_uar;
	int			sc_first_qp;

	struct mlx_dmamem	*sc_doorbells;

	int			sc_eqc_num;
	bus_size_t		sc_eqc_db;
	int			sc_eqc_cons;
	struct mlx_dmamem	*sc_eqe;
	struct mlx_mtt_range	sc_eqe_mttr;

	int			sc_nports;
	struct mlx_softc	*sc_ports[MLX_MAX_PORTS];
};

struct mlx_cq {
	int			cq_num;
	int			cq_uar;
	int			cq_arm;
	int			cq_cons;
	uint32_t		*cq_doorbell;
	struct mlx_dmamem	*cq_entries;
	struct mlx_mtt_range	cq_mttr;

};

struct mlx_slot {
	bus_dmamap_t		ms_map;
	struct mbuf		*ms_m;
};

struct mlx_qp {
	int			qp_num;
	int			qp_uar;
	uint32_t		*qp_rx_doorbell;
	uint64_t		qp_rx_db_addr;
	bus_size_t		qp_tx_doorbell;

	struct mlx_dmamem	*qp_wqe;
	struct mlx_send_wqe	*qp_send_wqe;
	struct mlx_recv_wqe	*qp_recv_wqe;
	struct mlx_mtt_range	qp_mttr;

	struct if_rxring	qp_rxr;
	struct mlx_slot		*qp_rx_slots;
	uint32_t		qp_rx_prod;
	uint32_t		qp_rx_prod_db;
	uint32_t		qp_rx_cons;

	struct mlx_slot		*qp_tx_slots;
	uint32_t		qp_tx_cons;
	uint32_t		qp_tx_prod;
	uint32_t		qp_tx_ring_count;
};

struct mlx_softc {
	struct device		sc_dev;
	TAILQ_ENTRY(mlx_softc)	sc_link;

	struct arpcom		sc_ac;
	struct ifmedia		sc_media;
	int			sc_active_media;

	struct mlxc_softc	*sc_mlxc;
	int			sc_port;
	int			sc_max_macs;

	struct mlx_qp		sc_qp;

	/* rx */
	struct mlx_cq		sc_rx_cq;

	/* tx */
	struct mlx_cq		sc_tx_cq;
};

struct mlx_attach_args {
	int			maa_port;
	struct mlx_port_cap	*maa_port_cap;
};

#define DEVNAME(_sc) ((_sc)->sc_dev.dv_xname)

static int	mlxc_match(struct device *, void *, void *);
static void	mlxc_attach(struct device *, struct device *, void *);
int	mlxc_detach(struct device *, int);
int	mlxc_print(void *, const char *);

static int	mlx_match(struct device *, void *, void *);
static void	mlx_attach(struct device *, struct device *, void *);
int	mlx_detach(struct device *, int);

int	mlx_media_change(struct ifnet *);
void	mlx_media_status(struct ifnet *, struct ifmediareq *);

void	mlx_watchdog(struct ifnet *);
int	mlx_ioctl(struct ifnet *, u_long, caddr_t);
void	mlx_start(struct ifqueue *);

int	mlx_rxrinfo(struct mlx_softc *, struct if_rxrinfo *);
int	mlx_up(struct mlx_softc *);
void	mlx_down(struct mlx_softc *);

int	mlx_buf_fill(struct mlx_softc *, struct mlx_slot *);
int	mlx_rx_fill_slots(struct mlx_softc *, struct mlx_qp *, u_int);
int	mlx_rx_fill(struct mlx_softc *, struct mlx_qp *);

int	mlx_prepare_qp(struct mlx_softc *, struct mlx_qp *, int, int, int);
int	mlx_init_qp(struct mlx_softc *, struct mlx_qp *);
void	mlx_destroy_qp(struct mlx_softc *, struct mlx_qp *);

int	mlx_create_cq(struct mlxc_softc *, struct mlx_cq *, int, int, int);
void	mlx_arm_cq(struct mlxc_softc *, struct mlx_cq *);
void	mlx_destroy_cq(struct mlxc_softc *, struct mlx_cq *);

void	mlx_process_tx_cq(struct mlx_softc *);
void	mlx_process_rx_cq(struct mlx_softc *);

struct mlx_dmamem *mlx_dmamem_alloc(struct mlxc_softc *, size_t, size_t);
void	mlx_dmamem_free(struct mlxc_softc *, struct mlx_dmamem *);
int	mlx_fw_setup(struct mlxc_softc *);
int	mlx_mod_stat_cfg(struct mlxc_softc *);
int	mlx_get_device_info(struct mlxc_softc *);
int	mlx_allocate_icm(struct mlxc_softc *);
int	mlx_init_hca(struct mlxc_softc *);
int	mlx_write_mtt(struct mlxc_softc *, uint64_t, uint64_t, int,
	    struct mlx_mtt_range *);
int	mlx_prepare(struct mlxc_softc *);
int	mlx_intr(void *);

int	mlx_pending(struct mlxc_softc *);
void	mlx_cmd(struct mlxc_softc *, uint64_t, uint64_t, uint32_t, uint8_t,
	    uint16_t, uint16_t, int);
int	mlx_poll_cmd(struct mlxc_softc *, int);
int	mlx_mbox_in(struct mlxc_softc *, uint32_t, uint8_t, uint16_t, int);
int	mlx_mbox_out(struct mlxc_softc *, uint32_t, uint8_t, uint16_t, int);
int	mlx_cmd_imm(struct mlxc_softc *, uint32_t, uint8_t, uint16_t, int,
	    uint64_t, uint64_t *);

struct cfattach mlxc_ca = {
	sizeof(struct mlxc_softc),
	mlxc_match,
	mlxc_attach,
	mlxc_detach
};

struct cfdriver mlxc_cd = {
	NULL, "mlxc", DV_DULL
};

struct cfattach mlx_ca = {
	sizeof(struct mlx_softc),
	mlx_match,
	mlx_attach,
	mlx_detach
};

struct cfdriver mlx_cd = {
	NULL, "mlx", DV_IFNET
};

static const struct pci_matchid mlx_devices[] = {
	{ PCI_VENDOR_MELLANOX,	PCI_PRODUCT_MELLANOX_CONNECTX3_EN }
};

static int
mlxc_match(struct device *parent, void *match, void *aux)
{
	return (pci_matchbyid(aux, mlx_devices, nitems(mlx_devices)));
}


void
dump_stuff(void *buf, int n)
{
	uint8_t *d = buf;
	int l;

	for (l = 0; l < n; l++) {
		printf(" %2.2x", d[l]);
		if (l % 16 == 15)
			printf("\n");
	}
	if (n % 16 != 0)
		printf("\n");
}

int
mlx_fw_setup(struct mlxc_softc *sc)
{
	struct mlx_query_fw		*query_fw;
	struct mlx_map_mem		*map_mem;
	uint64_t			 dva;
	size_t				 fwsize;
	int				 nareas, i;		

	if (mlx_mbox_out(sc, 0, 0, MLX_CMD_QUERY_FW, 100) != 0) {
		printf(": QUERY_FW failed\n");
		return 1;
	}
	query_fw = (struct mlx_query_fw *)MLX_DMA_KVA(sc->sc_mbox);

	if (betoh16(query_fw->cmd_interface_rev) != MLX_CMD_INTF_REV) {
		printf(": unsupported interface version %x\n",
		    query_fw->cmd_interface_rev);
		return 1;
	}
	printf(" firmware %d.%d.%03d (%x/%x/%x)",
	    betoh16(query_fw->fw_rev_major),
	    betoh16(query_fw->fw_rev_minor),
	    betoh16(query_fw->fw_rev_subminor), query_fw->fw_day,
	    query_fw->fw_month, betoh16(query_fw->fw_year));

	if (query_fw->clr_int_bar != 0) {
		printf("don't know how to clear interrupts in bar %d\n",
		    query_fw->clr_int_bar);
		return 1;
	}

	sc->sc_clr_offset = betoh32(query_fw->clr_int_hi);
	sc->sc_clr_offset <<= 32;
	sc->sc_clr_offset |= betoh32(query_fw->clr_int_lo);

	/* allocate firmware area in 64kb chunks */
	fwsize = betoh16(query_fw->fw_pages) * MLX_PAGE_SIZE;
	nareas = (fwsize + MLX_FWAREA_CHUNK - 1) / MLX_FWAREA_CHUNK;
	if (nareas > (MLX_MBOX_SIZE / sizeof(struct mlx_map_mem))) {
		printf(", fw area is too big (%ld bytes)\n", fwsize);
		return 1;
	}

	sc->sc_fw_areas = mallocarray(nareas, sizeof(struct mlx_dmamem *),
	    M_DEVBUF, M_NOWAIT | M_ZERO);
	if (sc->sc_fw_areas == NULL) {
		printf(", unable to allocate fw areas\n");
		return 1;
	}

	map_mem = (struct mlx_map_mem *)MLX_DMA_KVA(sc->sc_mbox);
	memset(map_mem, 0, MLX_MBOX_SIZE);
	for (i = 0; i < nareas; i++) {
		sc->sc_fw_areas[i] = mlx_dmamem_alloc(sc, MLX_FWAREA_CHUNK,
		    MLX_FWAREA_CHUNK);
		if (sc->sc_fw_areas[i] == NULL) {
			printf(", unable to allocate fw chunk %d\n", i);
			nareas = i;
			goto free_chunks;
		}

		dva = MLX_DMA_DVA(sc->sc_fw_areas[i]);
		KASSERT((dva & 0xFFF) == 0);
		map_mem->pa_h = htobe32(dva >> 32);
		map_mem->pa_l_size = htobe32((dva & 0xFFFFF000UL) |
		    (MLX_FWAREA_CHUNK_SHIFT - MLX_PAGE_SHIFT));
		map_mem++;
	}
	if (mlx_mbox_in(sc, nareas, 0, MLX_CMD_MAP_FA, 100) != 0) {
		printf(", unable to map fw areas\n");
		goto free_chunks;
	}

	/* this takes a while */
	if (mlx_mbox_in(sc, 0, 0, MLX_CMD_RUN_FW, 10000) != 0) {
		printf(", RUN_FW failed\n");
		goto free_chunks;
	}
	
	return 0;

free_chunks:
	for (i = 0; i < nareas; i++) {
		mlx_dmamem_free(sc, sc->sc_fw_areas[i]);
	}
	free(sc->sc_fw_areas, M_DEVBUF, nareas * sizeof(struct mlx_dmamem *));
	return 1;
}

int
mlx_mod_stat_cfg(struct mlxc_softc *sc)
{
	struct mlx_mod_stat_cfg		*mod_stat_cfg;

	mod_stat_cfg = (struct mlx_mod_stat_cfg *)MLX_DMA_KVA(sc->sc_mbox);
	memset(mod_stat_cfg, 0, MLX_MBOX_SIZE);

	mod_stat_cfg->pg_sz_m = 1;
	mod_stat_cfg->pg_sz = 0;

	if (mlx_mbox_in(sc, 0, 0, MLX_CMD_MOD_STAT_CFG, 100) != 0) {
		printf(": MOD_STAT_CFG failed\n");
		return 1;
	}

	return 0;
}

int
mlx_get_device_info(struct mlxc_softc *sc)
{
	void *buf;

	buf = MLX_DMA_KVA(sc->sc_mbox);
	memset(buf, 0, MLX_MBOX_SIZE);
	if (mlx_mbox_out(sc, 0, 0, MLX_CMD_QUERY_DEV_CAP, 1000) != 0) {
		return 1;
	}

	memcpy(&sc->sc_dev_cap, buf, sizeof(sc->sc_dev_cap));

	printf(" %d ports\n", sc->sc_dev_cap.mtu_max_port_width & 0xf);
	printf(" cap flags_ext %x, cap flags %x\n", sc->sc_dev_cap.flags_ext,
	    sc->sc_dev_cap.flags);
	printf("min page size %d, uar size %d, %d rsvd uars\n",
	    (1 << sc->sc_dev_cap.log_pg_sz),
	    (1 << ((sc->sc_dev_cap.log_uar_sz & 0x3f) + 20)),
	    sc->sc_dev_cap.rsvd_uar >> 4);
	printf("pd: max %d, rsvd %d\n", (1 << (sc->sc_dev_cap.log_max_pd & 0x3f)),
	    sc->sc_dev_cap.num_rsvd_pds >> 4);
	printf("mpt: cmpt size %d, dmpt size %d, %d rsvd mrws\n",
	    betoh16(sc->sc_dev_cap.c_mpt_entry_sz),
	    betoh16(sc->sc_dev_cap.d_mpt_entry_sz),
	    1 << (sc->sc_dev_cap.log_rsvd_mrws & 0xf));
	printf("qp: max %d, rsvd %d, size %d, entry size %d\n",
	    (1 << (sc->sc_dev_cap.log_max_qp & 0xf)),
	    (1 << (sc->sc_dev_cap.log_rsvd_qp & 0xf)),
	    (1 << sc->sc_dev_cap.log_max_qp_sz),
	    betoh16(sc->sc_dev_cap.qpc_entry_sz));
	printf("srq: max %d, rsvd %d\n", (1 << (sc->sc_dev_cap.log_max_srqs & 0x1f)),
	    (1 << (sc->sc_dev_cap.log_rsvd_srqs >> 4)));
	printf("cq: max %d, rsvd %d, size %d, entry size %d\n",
	    (1 << (sc->sc_dev_cap.log_max_cqs & 0x1f)),
	    (1 << (sc->sc_dev_cap.log_rsvd_cqs & 0xf)),
	    (1 << sc->sc_dev_cap.log_max_cq_sz),
	    betoh16(sc->sc_dev_cap.cqc_entry_sz));
	printf("eq: max %d, rsvd %d, entry size %d\n",
	    (1 << (sc->sc_dev_cap.log_max_eqs & 0xf)),
	    (1 << (sc->sc_dev_cap.log_rsvd_eqs & 0xf)),
	    betoh16(sc->sc_dev_cap.eqc_entry_sz));
	printf("mtt: max %d, rsvd %d, entry size %d\n",
	    (1 << sc->sc_dev_cap.log_max_mtt_seg),
	    (1 << (sc->sc_dev_cap.log_rsvd_mtts >> 4)),
	    betoh16(sc->sc_dev_cap.mtt_entry_sz));
	printf("send queue: max entry size %d, sgl size %d\n",
	    betoh16(sc->sc_dev_cap.max_desc_sz_sq), sc->sc_dev_cap.max_sg_sq);
	printf("receive queue: max entry size %d, sgl size %d\n",
	    betoh16(sc->sc_dev_cap.max_desc_sz_rq), sc->sc_dev_cap.max_sg_rq);
	printf("lkey: reserved %08x\n", betoh32(sc->sc_dev_cap.resd_lkey));
	return 0;
}

int
alloc_count(int log_rsvd, int used)
{
	int l;
	int c = (1 << log_rsvd) + used;

	l = fls(c - 1);
	return l;
}

uint64_t
cmpt_block_len(int size, int entry_size)
{
	return roundup(((uint64_t)(1 << size)) * entry_size, MLX_PAGE_SIZE);
}

int
mlx_allocate_icm(struct mlxc_softc *sc)
{
	struct mlx_map_mem		*map_mem;
	int 				b, cmptsz, other_block;
	uint64_t 			icm_addr, other_base, len, total;
	uint64_t 			cmpt_block_size;
	uint64_t 			icm_aux_size;
	uint64_t 			dva;
	char				*other_ptr;

	sc->sc_qpcs = alloc_count(sc->sc_dev_cap.log_rsvd_qp & 0xf, MLX_ALLOC_QPS +
	    MLX_SPECIAL_QPS);
	sc->sc_srqs = alloc_count(sc->sc_dev_cap.log_rsvd_srqs >> 4, 0);
	sc->sc_cqcs = alloc_count(sc->sc_dev_cap.log_rsvd_cqs & 0xf, MLX_ALLOC_CQS);
	sc->sc_eqcs = alloc_count(sc->sc_dev_cap.log_rsvd_eqs & 0xf, MLX_ALLOC_EQS);
	sc->sc_mtts = alloc_count(sc->sc_dev_cap.log_rsvd_mtts >> 4,
	    MLX_ALLOC_MTTS);
	sc->sc_mpts = alloc_count(sc->sc_dev_cap.log_rsvd_mrws & 0xf,
	    MLX_ALLOC_MPTS);
	sc->sc_mcs = fls(MLX_ALLOC_MCS - 1);

	icm_addr = 0;
	total = 0;
	cmptsz = betoh16(sc->sc_dev_cap.c_mpt_entry_sz);
	cmpt_block_size = MLX_CMPT_BLOCK_SIZE * (uint64_t)cmptsz;

	b = 0;
	/* cmpt for qps */
	len = cmpt_block_len(sc->sc_qpcs, cmptsz);
	sc->sc_icm[b].icm_addr = icm_addr;
	sc->sc_icm[b].icm_len = len;
	printf("qp cmpt: %llx at %llx\n", sc->sc_icm[b].icm_len,
	    sc->sc_icm[b].icm_addr);
	icm_addr += cmpt_block_size;
	total += len;
	b++;

	/* cmpt for srqs */
	len = cmpt_block_len(sc->sc_srqs, cmptsz);
	sc->sc_icm[b].icm_addr = icm_addr;
	sc->sc_icm[b].icm_len = len;
	printf("srq cmpt: %llx at %llx\n", sc->sc_icm[b].icm_len,
	    sc->sc_icm[b].icm_addr);
	icm_addr += cmpt_block_size;
	total += len;
	b++;

	/* cmpt for cqs */
	len = cmpt_block_len(sc->sc_cqcs, cmptsz);
	sc->sc_icm[b].icm_addr = icm_addr;
	sc->sc_icm[b].icm_len = len;
	printf("cq cmpt: %llx at %llx\n", sc->sc_icm[b].icm_len,
	    sc->sc_icm[b].icm_addr);
	icm_addr += cmpt_block_size;
	total += len;
	b++;

	/* cmpt for eqs */
	len = cmpt_block_len(sc->sc_eqcs, cmptsz);
	sc->sc_icm[b].icm_addr = icm_addr;
	sc->sc_icm[b].icm_len = len;
	printf("eq cmpt: %llx at %llx\n", sc->sc_icm[b].icm_len,
	    sc->sc_icm[b].icm_addr);
	icm_addr += cmpt_block_size;
	total += len;
	b++;

	/* other blocks */
	other_block = b;
	other_base = icm_addr;
	sc->sc_icm[b].icm_addr = icm_addr;

	/* qp contexts */
	len = ((uint64_t)(1 << sc->sc_qpcs)) *
	    betoh16(sc->sc_dev_cap.qpc_entry_sz);
	icm_addr = roundup(icm_addr, len);
	sc->sc_qpc_addr = icm_addr;
	printf("qpc: %llx at %llx\n", len, icm_addr);
	total += len;
	icm_addr += len;

	/* alt contexts */
	len = ((uint64_t)(1 << sc->sc_qpcs)) *
	    betoh16(sc->sc_dev_cap.altc_entry_sz);
	icm_addr = roundup(icm_addr, len);
	sc->sc_altc_addr = icm_addr;
	printf("altc: %llx at %llx\n", len, icm_addr);
	total += len;
	icm_addr += len;

	/* aux contexts */
	len = ((uint64_t)(1 << sc->sc_qpcs)) *
	    betoh16(sc->sc_dev_cap.aux_entry_sz);
	icm_addr = roundup(icm_addr, len);
	sc->sc_auxc_addr = icm_addr;
	printf("auxc: %llx at %llx\n", len, icm_addr);
	total += len;
	icm_addr += len;

	/* srq contexts */
	len = ((uint64_t)(1 << sc->sc_srqs)) *
	    betoh16(sc->sc_dev_cap.srq_entry_sz);
	icm_addr = roundup(icm_addr, len);
	sc->sc_srqc_addr = icm_addr;
	printf("srqc: %llx at %llx\n", len, icm_addr);
	total += len;
	icm_addr += len;

	/* cq contexts */
	len = ((uint64_t)(1 << sc->sc_cqcs)) *
	    betoh16(sc->sc_dev_cap.cqc_entry_sz);
	icm_addr = roundup(icm_addr, len);
	sc->sc_cqc_addr = icm_addr;
	printf("cqc: %llx at %llx\n", len, icm_addr);
	total += len;
	icm_addr += len;

	/* eq contexts */
	len = ((uint64_t)(1 << sc->sc_eqcs)) *
	    betoh16(sc->sc_dev_cap.eqc_entry_sz);
	icm_addr = roundup(icm_addr, len);
	sc->sc_eqc_addr = icm_addr;
	printf("eqc: %llx at %llx\n", len, icm_addr);
	total += len;
	icm_addr += len;

	/* mtt */
	len = ((uint64_t)(1 << sc->sc_mtts)) *
	    betoh16(sc->sc_dev_cap.mtt_entry_sz);
	icm_addr = roundup(icm_addr, len);
	sc->sc_mtt_addr = icm_addr;
	printf("mtt: %llx at %llx\n", len, icm_addr);
	total += len;
	icm_addr += len;

	/* mpt */
	len = ((uint64_t)(1 << sc->sc_mpts)) *
	    betoh16(sc->sc_dev_cap.d_mpt_entry_sz);
	icm_addr = roundup(icm_addr, len);
	sc->sc_mpt_addr = icm_addr;
	printf("mpt %d: %llx at %llx\n", sc->sc_mpts, len, icm_addr);
	total += len;
	icm_addr += len;

	/* multicast */
	len = ((uint64_t)(1 << sc->sc_mcs)) * sizeof(struct mlx_mcg_entry);
	icm_addr = roundup(icm_addr, len);
	sc->sc_mcs_addr = icm_addr;
	printf("mcg: %llx at %llx\n", len, icm_addr);
	total += len;
	icm_addr += len;

	sc->sc_icm[b].icm_len = icm_addr - sc->sc_icm[b].icm_addr;
	b++;
	sc->sc_icm_blocks = b;

	/* get aux size */
	if (mlx_cmd_imm(sc, 0, 0, MLX_CMD_SET_ICM_SIZE, 100, icm_addr,
	    &icm_aux_size) != 0) {
		printf(": unable to get icm aux size\n");
		return 1;
	}
	printf("icm aux: %lld bytes for %lld bytes of icm up to %llx\n",
	    icm_aux_size * MLX_PAGE_SIZE, total, icm_addr);

	/* allocate and map icm aux */
	sc->sc_icm_aux = mlx_dmamem_alloc(sc, icm_aux_size * MLX_PAGE_SIZE,
	    MLX_FWAREA_CHUNK);
	if (sc->sc_icm_aux == NULL) {
		printf(": unable to allocate icm aux\n");
		return 1;
	}

	map_mem = (struct mlx_map_mem *)MLX_DMA_KVA(sc->sc_mbox);
	dva = MLX_DMA_DVA(sc->sc_icm_aux);
	map_mem->va_h = 0;
	map_mem->va_l = 0;

	for (icm_addr = 0; icm_addr < icm_aux_size * MLX_PAGE_SIZE;
	    icm_addr += MLX_FWAREA_CHUNK) {

		map_mem->pa_h = htobe32((dva + icm_addr) >> 32);
		map_mem->pa_l_size = htobe32(((dva + icm_addr) & 0xFFFFF000UL)
		    | (MLX_FWAREA_CHUNK_SHIFT - MLX_PAGE_SHIFT));
		if (mlx_mbox_in(sc, 1, 0, MLX_CMD_MAP_ICM_AUX, 100) != 0) {
			printf(": unable to map icm aux\n");
			goto free_icm_aux;
		}
	}

	/* allocate and map icm areas */
	map_mem = (struct mlx_map_mem *)MLX_DMA_KVA(sc->sc_mbox);
	for (b = 0; b < sc->sc_icm_blocks; b++) {
		int logsize;

		/* must be at least one mlx page */
		if (sc->sc_icm[b].icm_len < MLX_PAGE_SIZE)
			sc->sc_icm[b].icm_len = MLX_PAGE_SIZE;

		/* must be power of two sized and aligned */
		logsize = 0;
		while ((1 << logsize) < sc->sc_icm[b].icm_len)
			logsize++;

		sc->sc_icm[b].icm_mem = mlx_dmamem_alloc(sc,
		    sc->sc_icm[b].icm_len, 1 << logsize);
		if (sc->sc_icm[b].icm_mem == NULL) {
			printf(": unable to allocate %lld bytes of icm\n",
			    sc->sc_icm[b].icm_len);
			goto free_icm;
		}
		dva = MLX_DMA_DVA(sc->sc_icm[b].icm_mem);
		map_mem->va_h = htobe32(sc->sc_icm[b].icm_addr >> 32);
		map_mem->va_l = htobe32(sc->sc_icm[b].icm_addr & 0xFFFFFFFFUL);
		map_mem->pa_h = htobe32(dva >> 32);
		map_mem->pa_l_size = htobe32((dva & 0xFFFFF000UL) |
		    (logsize - MLX_PAGE_SHIFT));
		map_mem++;
	}

	if (mlx_mbox_in(sc, sc->sc_icm_blocks, 0, MLX_CMD_MAP_ICM, 100) != 0) {
		printf(": unable to map icm\n");
		goto free_icm;
	}

	/* pointers to parts of the 'other' block */
	other_ptr = MLX_DMA_KVA(sc->sc_icm[other_block].icm_mem);
	sc->sc_other_map = sc->sc_icm[other_block].icm_mem->mxm_map;

	sc->sc_mtt_offset = (sc->sc_mtt_addr - other_base);
	sc->sc_mtt_ptr = (struct mlx_mtt *)(other_ptr + sc->sc_mtt_offset);
	sc->sc_next_mtt = (1 << (sc->sc_dev_cap.log_rsvd_mtts >> 4));

	return 0;

free_icm:
	for (b = 0; b < sc->sc_icm_blocks; b++) {
		if (sc->sc_icm[b].icm_mem != NULL) {
			mlx_dmamem_free(sc, sc->sc_icm[b].icm_mem);
			sc->sc_icm[b].icm_mem = NULL;
		}
	}
free_icm_aux:
	mlx_dmamem_free(sc, sc->sc_icm_aux);
	sc->sc_icm_aux = NULL;
	return 1;
}

int
mlx_init_hca(struct mlxc_softc *sc)
{
	struct mlx_init_hca		*init;

	init = (struct mlx_init_hca *)MLX_DMA_KVA(sc->sc_mbox);
	memset(init, 0, sizeof(*init));

	init->version = MLX_INIT_VERSION;
	// cacheline size?
	init->flags = htobe32(MLX_INIT_FLAGS);	// UD address vector thing?
	init->mw_enable = htobe16(1 << 15);
	init->log_max_uars = fls(MLX_ALLOC_UARS - 1);;
	init->uar_page_sz = PAGE_SHIFT - MLX_PAGE_SHIFT;

	sc->sc_first_uar = MAX(sc->sc_dev_cap.rsvd_uar >> 4, MLX_EQ_UARS);

	init->qpc_base_addr_hi = htobe32(sc->sc_qpc_addr >> 32);
	init->qpc_base_addr_lo_count = htobe32((sc->sc_qpc_addr & 0xFFFFFFC0UL)
	    | sc->sc_qpcs);

	init->srqc_base_addr_hi = htobe32(sc->sc_srqc_addr >> 32);
	init->srqc_base_addr_lo_count = htobe32((sc->sc_srqc_addr &
	    0xFFFFFFC0UL) | sc->sc_srqs);

	init->cqc_base_addr_hi = htobe32(sc->sc_cqc_addr >> 32);
	init->cqc_base_addr_lo_count = htobe32((sc->sc_cqc_addr & 0xFFFFFFC0UL)
	    | sc->sc_cqcs);

	init->altc_base_addr_hi = htobe32(sc->sc_altc_addr >> 32);
	init->altc_base_addr_lo = htobe32(sc->sc_altc_addr & 0xFFFFFFFFUL);

	init->auxc_base_addr_hi = htobe32(sc->sc_auxc_addr >> 32);
	init->auxc_base_addr_lo = htobe32(sc->sc_auxc_addr & 0xFFFFFFFFUL);

	init->eqc_base_addr_hi = htobe32(sc->sc_eqc_addr >> 32);
	init->eqc_base_addr_lo_count = htobe32((sc->sc_eqc_addr & 0xFFFFFFC0UL)
	    | sc->sc_eqcs);

	init->mc_base_addr_hi = htobe32(sc->sc_mtt_addr >> 32);
	init->mc_base_addr_lo = htobe32(sc->sc_mtt_addr & 0xFFFFFFFFUL);
	init->mc_table_entry_sz = fls(sizeof(struct mlx_mcg_entry) - 1);
	init->mc_table_hash_sz = sc->sc_mcs - 1;
	init->mc_table_sz = sc->sc_mcs;

	init->dmpt_base_addr_hi = htobe32(sc->sc_mpt_addr >> 32);
	init->dmpt_base_addr_lo = htobe32(sc->sc_mpt_addr & 0xFFFFFFFFUL);
	init->log_dmpt_sz = sc->sc_mpts;

	init->mtt_base_addr_hi = htobe32(sc->sc_mtt_addr >> 32);
	init->mtt_base_addr_lo = htobe32(sc->sc_mtt_addr & 0xFFFFFFFFUL);

	return mlx_mbox_in(sc, 0, 0, MLX_CMD_INIT_HCA, 10000);
}

int
mlx_write_mtt(struct mlxc_softc *sc, uint64_t addr, uint64_t length,
    int present, struct mlx_mtt_range *mttr)
{
	struct mlx_mtt		*mtt;
	int			i, pages;

	mttr->mtt_page_offset = addr & (MLX_PAGE_SIZE - 1);
	pages = (length + mttr->mtt_page_offset + MLX_PAGE_SIZE - 1)
	    / MLX_PAGE_SIZE;
	if (mttr->mtt_num == 0) {
		mttr->mtt_num = sc->sc_next_mtt;
		mttr->mtt_addr = sc->sc_mtt_addr +
		    (mttr->mtt_num * betoh16(sc->sc_dev_cap.mtt_entry_sz));
		mttr->mtt_pages = pages;
		sc->sc_next_mtt += mttr->mtt_pages;
	} else {
		/* allocations can't change size */
		KASSERT(pages == mttr->mtt_pages);
	}

	addr -= mttr->mtt_page_offset;

	mtt = sc->sc_mtt_ptr + mttr->mtt_num;
	for (i = 0; i < mttr->mtt_pages; i++) {
		mtt->ptag_hi = htobe32(addr >> 32);
		mtt->ptag_lo = htobe32((addr & 0xFFFFFFFFUL) |
		    (present ? MLX_MTT_PRESENT : 0));
		mtt++;

		addr += MLX_PAGE_SIZE;
	}

	bus_dmamap_sync(sc->sc_dmat, sc->sc_other_map, sc->sc_mtt_offset +
	    (mttr->mtt_num * sizeof(struct mlx_mtt)),
	    mttr->mtt_pages * sizeof(struct mlx_mtt), BUS_DMASYNC_PREREAD);

	return 0;
}

int
mlx_setup_mpt(struct mlxc_softc *sc)
{
	struct mlx_mpt *mpt;
	int mpt_num;

	sc->sc_pd = sc->sc_dev_cap.num_rsvd_pds >> 4;
	mpt_num = (1 << (sc->sc_dev_cap.log_rsvd_mrws & 0xf));
	sc->sc_mpt = mpt_num /*| 0x77000000UL*/;
	sc->sc_mpt_key = (sc->sc_mpt >> 24) | (sc->sc_mpt << 8);

	mpt = (struct mlx_mpt *)MLX_DMA_KVA(sc->sc_mbox);
	memset(mpt, 0, sizeof(*mpt));
	mpt->flags = htobe32(MLX_MPT_FLAG_MIO | MLX_MPT_FLAG_REG_WIN |
	    MLX_MPT_FLAG_PA | MLX_MPT_FLAG_SW_OWNS | MLX_MPT_FLAG_LR |
	    MLX_MPT_FLAG_LW);
	mpt->mem_key = htobe32(sc->sc_mpt);
	mpt->pd_flags2 = htobe32(sc->sc_pd | MLX_MPT_PD_FLAG_EN_INV);
	/* start addr and mtt addr are 0 */
	mpt->len_hi = 0xFFFFFFFFUL;
	mpt->len_lo = 0xFFFFFFFFUL;
	mpt->entity_size = htobe32(MLX_PAGE_SHIFT);
	mpt->mtt_rep = htobe32(MLX_MPT_LEN64);
	if (mlx_mbox_in(sc, mpt_num, 0, MLX_CMD_SW2HW_MPT, 100) != 0) {
		printf(": couldn't create memory protection table\n");
		return 1;
	}

	return 0;
}

int
mlx_prepare(struct mlxc_softc *sc)
{
	struct mlx_eq_context *eqc;
	struct mlx_query_adapter *adapter;
	size_t eqe_size;
	int uars, special_qps;

	/* event queue */
	uars = sc->sc_dev_cap.rsvd_uar >> 4;
	sc->sc_eqc_num = MAX(uars, 1 << (sc->sc_dev_cap.log_rsvd_eqs & 0xf));
	sc->sc_eqc_db =
	    (MLX_PAGE_SIZE * (sc->sc_eqc_num / MLX_EQS_PER_UAR)) +
	    MLX_EQ_UAR_OFFSET +
	    (MLX_EQ_UAR_SIZE * (sc->sc_eqc_num % MLX_EQS_PER_UAR));
	sc->sc_eqc_cons = 0;

	eqe_size = MLX_ALLOC_EQES * sizeof(struct mlx_eq_entry);
	sc->sc_eqe = mlx_dmamem_alloc(sc, eqe_size, MLX_PAGE_SIZE);
	if (sc->sc_eqe == NULL) {
		printf(": couldn't allocate event queue entries\n");
		return 1;
	}

	mlx_write_mtt(sc, MLX_DMA_DVA(sc->sc_eqe), eqe_size, 1,
	    &sc->sc_eqe_mttr);

	eqc = (struct mlx_eq_context *)MLX_DMA_KVA(sc->sc_mbox);
	memset(eqc, 0, sizeof(*eqc));
	eqc->status = htobe32(MLX_EQC_STATUS_ARMED);
	eqc->page_offset = 0;
	eqc->log_eq_size = htobe32(fls(MLX_ALLOC_EQES - 1) << 24);
	eqc->intr = 0;					/* msi-x? */
	eqc->mtt_base_addr_hi_sz = htobe32(((sc->sc_eqe_mttr.mtt_addr >> 32) &
		0xFF) | ((PAGE_SHIFT - MLX_PAGE_SHIFT) << 24));
	eqc->mtt_base_addr_lo = htobe32(sc->sc_eqe_mttr.mtt_addr &
	    0xFFFFFFFFUL);
	if (mlx_mbox_in(sc, sc->sc_eqc_num, 0, MLX_CMD_SW2HW_EQ, 100) != 0) {
		printf(": couldn't create event queue\n");
		return 1;
	}

	/* get interrupt pin */
	adapter = (struct mlx_query_adapter *)MLX_DMA_KVA(sc->sc_mbox);
	memset(adapter, 0, sizeof(*adapter));
	if (mlx_mbox_out(sc, 0, 0, MLX_CMD_QUERY_ADAPTER, 100) != 0) {
		printf(": couldn't query adapter info\n");
		return 1;
	}
	sc->sc_clr_int = htobe64(1 << adapter->inta_pin);

	/* map all events to this queue */
	if (mlx_cmd_imm(sc, sc->sc_eqc_num, 0, MLX_CMD_MAP_EQ, 100,
	    0xFFFFFFFFFFFFFFFFULL, NULL) != 0) {
		printf(": couldn't map events to event queue\n");
		return 1;
	}

	bus_space_write_raw_4(sc->sc_memt_uar, sc->sc_memh_uar,
	    sc->sc_eqc_db, htobe32(1 << 31));

	/* special queue pairs */
	special_qps = roundup((1 << (sc->sc_dev_cap.log_rsvd_qp & 0xf)),
	    MLX_SPECIAL_QPS);
	sc->sc_first_qp = special_qps + MLX_SPECIAL_QPS;
	if (mlx_cmd_imm(sc, special_qps, 0, MLX_CMD_CONF_SPECIAL_QP, 100, 0,
	    NULL) != 0) {
		printf(": couldn't configure special qps\n");
		return 1;
	}

	sc->sc_first_cq = (1 << (sc->sc_dev_cap.log_rsvd_cqs & 0xf));

	/* allocate memory for cq doorbells */
	sc->sc_doorbells = mlx_dmamem_alloc(sc, MLX_MAX_PORTS *
	    MLX_DOORBELLS_PER_PORT * MLX_DOORBELL_STRIDE, PAGE_SIZE);
	if (sc->sc_doorbells == NULL) {
		printf(": couldn't allocate memory for doorbells\n");
		return 1;
	}

	return 0;
}

void
mlx_nop(struct device *dev)
{
	struct mlxc_softc *sc = (struct mlxc_softc *)dev;

	mlx_cmd(sc, 0, 0, 0, 0, MLX_CMD_NOP, 0xa5a5, 1);
}

int
mlxc_print(void *aux, const char *pnp)
{
	struct mlx_attach_args *maa = aux;

	if (pnp != NULL)
		printf("\"%s\" at %s", mlx_cd.cd_name, pnp);

	printf(" port %d", maa->maa_port);
	return UNCONF;
}

int
mlx_reset(struct mlxc_softc *sc)
{
	pcireg_t pciconfig[64];
	int i;

	for (i = 0; i < nitems(pciconfig); i++) {
		if (i == 22 || i == 23)
			pciconfig[i] = 0;
		else
			pciconfig[i] = pci_conf_read(sc->sc_pc, sc->sc_tag,
			    i*4);
	}

	bus_space_write_raw_4(sc->sc_memt_cfg, sc->sc_memh_cfg, MLX_RESET_BASE,
	    htobe32(MLX_RESET_MAGIC));

	delay(1000000);

	/* check that pci vendor exists again? */

	for (i = 0; i < nitems(pciconfig); i++) {
		if (i != 1)
			pci_conf_write(sc->sc_pc, sc->sc_tag, i*4,
			    pciconfig[i]);
	}
	pci_conf_write(sc->sc_pc, sc->sc_tag, 4, pciconfig[1]);
	return 0;
}

static void
mlxc_attach(struct device *parent, struct device *self, void *aux)
{
	struct mlxc_softc		*sc = (struct mlxc_softc *)self;
	struct pci_attach_args		*pa = aux;
	pcireg_t			memtype;
	pci_intr_handle_t		ih;
	int				b, i, found;

	sc->sc_pc = pa->pa_pc;
	sc->sc_tag = pa->pa_tag;
	sc->sc_dmat = pa->pa_dmat;

	memtype = pci_mapreg_type(sc->sc_pc, sc->sc_tag, MLX_PCI_CONFIG_BAR);
	if (pci_mapreg_map(pa, MLX_PCI_CONFIG_BAR, memtype, 0,
	    &sc->sc_memt_cfg, &sc->sc_memh_cfg, NULL,
	    &sc->sc_mems_cfg, 0) != 0) {
		printf(": unable to map config bar\n");
		return;
	}

	memtype = pci_mapreg_type(sc->sc_pc, sc->sc_tag, MLX_PCI_UAR_BAR);
	if (pci_mapreg_map(pa, MLX_PCI_UAR_BAR, memtype, 0,
	    &sc->sc_memt_uar, &sc->sc_memh_uar, NULL,
	    &sc->sc_mems_uar, 0) != 0) {
		printf(": unable to map UAR bar\n");
		goto unmap_cfg;
	}

	sc->sc_mbox = mlx_dmamem_alloc(sc, MLX_MBOX_SIZE, PAGE_SIZE);
	if (sc->sc_mbox == NULL) {
		printf(": unable to allocate mbox buffer\n");
		goto unmap_uar;
	}

	if (mlx_reset(sc) != 0)
{ printf("reset failed\n");
		goto unmap_uar;
}

	if (mlx_fw_setup(sc) != 0)
{ printf("fw_setup failed\n");
		goto unmap_uar;
}

	if (mlx_mod_stat_cfg(sc) != 0)
{ printf("mlx_mod_stat_cfg failed\n");
		goto unmap_uar;
}

	/* get device info, port types */
	if (mlx_get_device_info(sc) != 0) {
		printf(": unable to get device info\n");
		goto unmap_uar;
	}

	if (mlx_allocate_icm(sc) != 0)
{ printf("allocate_icm failed\n");
		goto unmap_uar;
}

	if (mlx_init_hca(sc) != 0)
{ printf("init_hca failed\n");
		goto free_icm;
}

	if (mlx_setup_mpt(sc) != 0)
{ printf("setup_mpt failed\n");
		goto free_icm;
}

	if (mlx_prepare(sc) != 0)
		goto free_icm;

	/* msi, msi-x? */
	if (/*pci_intr_map_msix(pa, 0, &ih) &&*/ pci_intr_map(pa, &ih)) {
		printf(": unable to map interrupt\n");
		goto unmap_uar;
	}

	sc->sc_ih = pci_intr_establish(sc->sc_pc, ih, IPL_NET, mlx_intr, sc,
	    sc->sc_dev.dv_xname);
	if (sc->sc_ih == NULL) {
		printf("%s: unable to establish interrupt\n",
		    sc->sc_dev.dv_xname);
		goto unmap_uar;
	}
	printf(": %s\n", pci_intr_string(sc->sc_pc, ih));

	config_mountroot(&sc->sc_dev, mlx_nop);

	sc->sc_nports = MIN(sc->sc_dev_cap.mtu_max_port_width & 0xf, MLX_MAX_PORTS);

	found = 0;
	for (i = 0; i < sc->sc_nports; i++) {
		struct mlx_attach_args maa;

		maa.maa_port = i;
		maa.maa_port_cap =
		    (struct mlx_port_cap *)MLX_DMA_KVA(sc->sc_mbox);
		memset(maa.maa_port_cap, 0, sizeof(*maa.maa_port_cap));
		if (mlx_mbox_out(sc, i + 1, 0, MLX_CMD_QUERY_PORT, 100) != 0) {
			printf("query port %d failed\n", i);
			continue;
		}
		if (betoh32(maa.maa_port_cap->mtus) & MLX_PORT_CAP_ETH) {
			sc->sc_ports[i] = (struct mlx_softc *)config_found(self,
			    &maa, mlxc_print);
			found++;
		}
	}

	if (found == 0) {
		printf("%s: no ethernet capable ports found\n",
		    sc->sc_dev.dv_xname);
	}

	return;

/*
detach:
	mlxc_detach(sc, DETACH_FORCE|DETACH_QUIET); */
free_icm:
	for (b = 0; b < sc->sc_icm_blocks; b++) {
		mlx_dmamem_free(sc, sc->sc_icm[b].icm_mem);
	}
	mlx_dmamem_free(sc, sc->sc_icm_aux);
	sc->sc_icm_blocks = 0;
	sc->sc_icm_aux = NULL;
unmap_uar:
	bus_space_unmap(sc->sc_memt_uar, sc->sc_memh_uar, sc->sc_mems_uar);
	sc->sc_mems_uar = 0;
unmap_cfg:
	bus_space_unmap(sc->sc_memt_cfg, sc->sc_memh_cfg, sc->sc_mems_cfg);
	sc->sc_mems_cfg = 0;
}

int
mlxc_detach(struct device *self, int flags)
{
	struct mlxc_softc		*sc = (struct mlxc_softc *)self;
	int rv;

	if (sc->sc_ih)
		pci_intr_disestablish(sc->sc_pc, sc->sc_ih);

	rv = config_detach_children(self, flags);
	if (rv != 0)
		return rv;

	/* destroy dma maps? */

	/* bus_space_unmap? */

	return rv;
}

static int
mlx_match(struct device *parent, void *match, void *aux)
{
	return 1;
}


static void
mlx_attach(struct device *parent, struct device *self, void *aux)
{
	struct mlxc_softc 		*csc;
	struct mlx_softc 		*sc;
	struct mlx_attach_args		*maa = aux;
	struct ifnet			*ifp;
	uint64_t			mac;
	int				i;

	csc = (struct mlxc_softc *)parent;
	sc = (struct mlx_softc *)self;
	sc->sc_mlxc = csc;
	sc->sc_port = maa->maa_port;
	sc->sc_max_macs = 1 << (maa->maa_port_cap->log_max_mac_vlan & 0x0f);

	mac = betoh16(maa->maa_port_cap->mac_hi);
	mac <<= 32;
	mac |= betoh32(maa->maa_port_cap->mac_lo);
	for (i = 0; i < sizeof(sc->sc_ac.ac_enaddr); i++) {
		sc->sc_ac.ac_enaddr[i] = (uint8_t)(mac >>
		    ((sizeof(sc->sc_ac.ac_enaddr) - i - 1) * NBBY));
	}
	
	ifp = &sc->sc_ac.ac_if;
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_xflags = IFXF_MPSAFE;
	ifp->if_ioctl = mlx_ioctl;
	ifp->if_qstart = mlx_start;
	ifp->if_watchdog = mlx_watchdog;
	ifp->if_hardmtu = betoh32(maa->maa_port_cap->mtus) & 0xffff;
	strlcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);
	ifq_set_maxlen(&ifp->if_snd, 1);

	/* not yet
	ifp->if_capabilities = IFCAP_VLAN_MTU;
	ifp->if_capabilities |= IFCAP_VLAN_HWTAGGING;
	ifp->if_capabilities |= IFCAP_CSUM_IPv4;
	ifp->if_capabilities |= IFCAP_CSUM_TCPv4;
	ifp->if_capabilities |= IFCAP_CSUM_UDPv4;
	possibly v6 too?
	*/

	ifmedia_init(&sc->sc_media, 0, mlx_media_change, mlx_media_status);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_FDX | IFM_10G_SR, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_FDX | IFM_10G_SFP_CU, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_FDX | IFM_40G_CR4, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);

	if_attach(ifp);
	ether_ifattach(ifp);

	printf("\n");
}

int
mlx_detach(struct device *self, int flags)
{
	/* things */
	return 0;
}

int
mlx_media_change(struct ifnet *ifp)
{
	/* ignore? */
	return 0;
}

void
mlx_media_status(struct ifnet *ifp, struct ifmediareq *req)
{
        struct mlx_softc *sc = ifp->if_softc;

	req->ifm_status = IFM_AVALID;
	req->ifm_active = sc->sc_active_media | IFM_ETH_TXPAUSE | IFM_ETH_RXPAUSE;
	if (sc->sc_active_media != IFM_ETHER)
		req->ifm_status |= IFM_ACTIVE;
}

void
mlx_watchdog(struct ifnet *ifp)
{
}

int
mlx_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct mlx_softc	*sc = (struct mlx_softc *)ifp->if_softc;
	struct ifreq		*ifr = (struct ifreq *)data;
	int			s, error = 0;

	s = splnet();

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		/* FALLTHROUGH */

	case SIOCSIFFLAGS:
		if (ISSET(ifp->if_flags, IFF_UP)) {
			if (ISSET(ifp->if_flags, IFF_RUNNING))
				error = ENETRESET;
			else
				error = mlx_up(sc);
		} else {
			if (ISSET(ifp->if_flags, IFF_RUNNING))
				mlx_down(sc);
		}
		break;

	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;

	case SIOCGIFRXR:
		error = mlx_rxrinfo(sc, (struct if_rxrinfo *)ifr->ifr_data);
		break;

	default:
		error = ether_ioctl(ifp, &sc->sc_ac, cmd, data);
		break;
	}

	if (error == ENETRESET) {
                if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
                    (IFF_UP | IFF_RUNNING)) {
			/* mlx_iff(sc); */
		}
		error = 0;
	}

	splx(s);
	return error;
}

int
mlx_rxrinfo(struct mlx_softc *sc, struct if_rxrinfo *ifri)
{
	struct if_rxring_info ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_size = 1500;
	ifr.ifr_info = sc->sc_qp.qp_rxr;

	return if_rxr_info_ioctl(ifri, 1, &ifr);
}

int
mlx_load_mbuf(struct mlx_softc *sc, struct mlx_slot *slot, struct mbuf *m)
{
	bus_dma_tag_t dmat = sc->sc_mlxc->sc_dmat;
	bus_dmamap_t dmap = slot->ms_map;

	switch (bus_dmamap_load_mbuf(dmat, dmap, m,
	    BUS_DMA_STREAMING | BUS_DMA_NOWAIT)) {
	case 0:
		break;

	case EFBIG: /* mbuf chain is too fragmented */
		if (m_defrag(m, M_DONTWAIT) == 0 &&
		   bus_dmamap_load_mbuf(dmat, dmap, m,
		   BUS_DMA_STREAMING | BUS_DMA_NOWAIT) == 0)
			break;

	default:
		return (1);
	}

	slot->ms_m = m;
	return (0);
}

void
mlx_start(struct ifqueue *ifq)
{
	struct ifnet *ifp = ifq->ifq_if;
	struct mlx_softc *sc = ifp->if_softc;
	struct mlx_qp *qp = &sc->sc_qp;
	u_int idx, cons, prod;
	u_int free, used = 0;
	struct mbuf *m;
	struct mlx_slot *ms;

	idx = qp->qp_tx_prod;
	free = qp->qp_tx_cons;
	if (free <= idx)
		free += qp->qp_tx_ring_count;
	free -= idx;

	cons = prod = qp->qp_tx_prod;

	for (;;) {
		/* currently forcing every packet to fit in one tx wqe */
		if (used + 1 > free) {
			ifq_set_oactive(ifq);
			break;
		}

		m = ifq_dequeue(ifq);
		if (m == NULL)
			break;

		ms = &qp->qp_tx_slots[prod];
		if (mlx_load_mbuf(sc, ms, m) != 0) {
			m_freem(m);
			ifp->if_oerrors++;
			continue;
		}

#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif

		bus_dmamap_sync(sc->sc_mlxc->sc_dmat, ms->ms_map, 0, ms->ms_map->dm_mapsize,
		    BUS_DMASYNC_PREWRITE);

		used++;
		if (++prod >= qp->qp_tx_ring_count)
			prod = 0;
	}
	
	if (cons == prod)
		return;

	/* start tx queue somehow */

	/* update prod idx */
	qp->qp_tx_prod = idx;
}

int
mlx_create_cq(struct mlxc_softc *sc, struct mlx_cq *cq, int cqn, int uar, int dbn)
{
	struct mlx_cq_context *cqc;
	size_t cqe_size, db_offset;
	uint64_t db_addr;

	db_offset = dbn * MLX_DOORBELL_STRIDE;
	db_addr = MLX_DMA_DVA(sc->sc_doorbells) + db_offset;
	cq->cq_doorbell = (uint32_t *)(MLX_DMA_KVA(sc->sc_doorbells) + db_offset);
	cq->cq_num = cqn;
	cq->cq_uar = uar;

	cqe_size = MLX_ALLOC_CQES * sizeof(struct mlx_cq_entry);
	cq->cq_entries = mlx_dmamem_alloc(sc, cqe_size, MLX_PAGE_SIZE);
	if (cq->cq_entries == NULL) {
		printf("%s: couldn't allocate completion queue entries\n",
		    DEVNAME(sc));
		return 1;
	}

	mlx_write_mtt(sc, MLX_DMA_DVA(cq->cq_entries), cqe_size, 1,
	    &cq->cq_mttr);

	cqc = (struct mlx_cq_context *)MLX_DMA_KVA(sc->sc_mbox);
	memset(cqc, 0, sizeof(*cqc));
	cqc->logsize_uarpage = htobe32(uar | (fls(MLX_ALLOC_CQES - 1) << 24));
	cqc->comp_eqn = htobe32(sc->sc_eqc_num);
	cqc->mtt_base_addr_hi_sz = htobe32(((cq->cq_mttr.mtt_addr >> 32) &
		0xFF) | ((PAGE_SHIFT - MLX_PAGE_SHIFT) << 24));
	cqc->mtt_base_addr_lo = htobe32(cq->cq_mttr.mtt_addr &
	    0xFFFFFFFFUL);
	cqc->db_rec_addr_hi = htobe32(db_addr >> 32);
	cqc->db_rec_addr_lo = htobe32(db_addr & 0xFFFFFFFFUL);
	if (mlx_mbox_in(sc, cq->cq_num, 0, MLX_CMD_SW2HW_CQ, 100) != 0) {
		printf("%s: couldn't create completion queue %d\n",
		    DEVNAME(sc), cq->cq_num);
		return 1;
	}

	return 0;
}

void
mlx_arm_cq(struct mlxc_softc *sc, struct mlx_cq *cq)
{
	uint32_t sn;
	uint32_t ci;
	uint64_t uar;

	cq->cq_arm++;
	sn = cq->cq_arm & 3;
	ci = cq->cq_cons & 0xffffff;

	cq->cq_doorbell[1] = htobe32(sn << 28 | (1 << 24) | ci);
	membar_sync();

	uar = htobe32(ci);
	uar<<= 32;
	uar |= htobe32(sn << 28 | (1 << 24) | cq->cq_num);
	bus_space_write_raw_8(sc->sc_memt_uar, sc->sc_memh_uar,
	   (cq->cq_uar * MLX_PAGE_SIZE) + MLX_UAR_CQ_DOORBELL , uar);
}

void
mlx_destroy_cq(struct mlxc_softc *sc, struct mlx_cq *cq)
{
	if (cq->cq_entries == NULL)
		return;

	mlx_write_mtt(sc, 0, cq->cq_entries->mxm_size, 0, &cq->cq_mttr);
	mlx_dmamem_free(sc, cq->cq_entries);
	cq->cq_entries = NULL;
}

int
mlx_prepare_qp(struct mlx_softc *sc, struct mlx_qp *qp, int qpn, int dbn, int uar)
{
	struct mlx_slot *ms;
	uint32_t wqe_size;
	size_t db_offset;
	int i, seg, rv;

	qp->qp_num = qpn;
	qp->qp_uar = uar;

	/* work queue entries */
	wqe_size = (MLX_ALLOC_RX_WQES * sizeof(struct mlx_recv_wqe)) +
	    (MLX_ALLOC_TX_WQES * sizeof(struct mlx_send_wqe));
	qp->qp_wqe = mlx_dmamem_alloc(sc->sc_mlxc, wqe_size, MLX_PAGE_SIZE);
	if (qp->qp_wqe == NULL)
		return ENOMEM;

	mlx_write_mtt(sc->sc_mlxc, MLX_DMA_DVA(qp->qp_wqe), wqe_size, 1,
	    &qp->qp_mttr);

	qp->qp_send_wqe = (struct mlx_send_wqe *)MLX_DMA_KVA(qp->qp_wqe);
	qp->qp_recv_wqe = (struct mlx_recv_wqe *)(qp->qp_send_wqe +
	    MLX_ALLOC_TX_WQES);
	printf("qp wqes at %p, %d send wqes, rx wqes at %p\n", qp->qp_send_wqe,
	    MLX_ALLOC_TX_WQES, qp->qp_recv_wqe);

	/* rx ring */
	qp->qp_rx_slots = mallocarray(sizeof(*ms), MLX_ALLOC_RX_WQES,
	    M_DEVBUF, M_WAITOK | M_ZERO);
	if (qp->qp_rx_slots == NULL) {
		rv = ENOMEM;
		goto destroy_wqe;
	}

	for (i = 0; i < MLX_ALLOC_TX_WQES; i++) {
		memset(&qp->qp_send_wqe[i], 0xff, sizeof(struct mlx_send_wqe));
	}

	for (i = 0; i < MLX_ALLOC_RX_WQES; i++) {
		ms = &qp->qp_rx_slots[i];
		rv = bus_dmamap_create(sc->sc_mlxc->sc_dmat, MCLBYTES, 1,
		    MCLBYTES, 0, BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW,
		    &ms->ms_map);
		if (rv != 0)
			goto destroy_rx_slots;

		for (seg = 0; seg < MLX_RECV_WQE_SEGS; seg++) {
			qp->qp_recv_wqe[i].segs[seg].lkey =
			    htobe32(MLX_INVALID_LKEY);
		}
	}

	if_rxr_init(&qp->qp_rxr, 2, MLX_ALLOC_RX_WQES); /* min size? */

	/* rx doorbell */
	db_offset = dbn * MLX_DOORBELL_STRIDE;
	qp->qp_rx_doorbell = (uint32_t *)(MLX_DMA_KVA(sc->sc_mlxc->sc_doorbells) + db_offset);
	qp->qp_rx_db_addr = MLX_DMA_DVA(sc->sc_mlxc->sc_doorbells) + db_offset;

	/* tx ring */
	qp->qp_tx_slots = mallocarray(sizeof(*ms), MLX_ALLOC_TX_WQES,
	    M_DEVBUF, M_WAITOK);
	if (qp->qp_tx_slots == NULL) {
		rv = ENOMEM;
		goto destroy_rx_slots;
	}

	for (i = 0; i < MLX_ALLOC_TX_WQES; i++) {
		ms = &qp->qp_tx_slots[i];
		/* # segments, alignment? */
		rv = bus_dmamap_create(sc->sc_mlxc->sc_dmat, MCLBYTES, 2,
		    PAGE_SIZE, PAGE_SIZE, BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW,
		    &ms->ms_map);
		if (rv != 0)
			goto destroy_tx_slots;
	}

	return 0;

destroy_tx_slots:
	while (i-- > 0) {
		ms = &sc->sc_qp.qp_tx_slots[i];
		bus_dmamap_destroy(sc->sc_mlxc->sc_dmat, ms->ms_map);
	}
	free(sc->sc_qp.qp_tx_slots, M_DEVBUF, sizeof(*ms) * MLX_ALLOC_TX_WQES);
destroy_rx_slots:
	while (i-- > 0) {
		ms = &sc->sc_qp.qp_rx_slots[i];
		bus_dmamap_destroy(sc->sc_mlxc->sc_dmat, ms->ms_map);
	}
	free(sc->sc_qp.qp_rx_slots, M_DEVBUF, sizeof(*ms) * MLX_ALLOC_RX_WQES);
destroy_wqe:
	mlx_write_mtt(sc->sc_mlxc, 0, wqe_size, 0, &qp->qp_mttr);
	mlx_dmamem_free(sc->sc_mlxc, qp->qp_wqe);

	return rv;
}

int
mlx_init_qp(struct mlx_softc *sc, struct mlx_qp *qp)
{
	struct mlx_qp_state *qps;

	qps = (struct mlx_qp_state *)MLX_DMA_KVA(sc->sc_mlxc->sc_mbox);
	memset(qps, 0, sizeof(*qps));

	qps->c.state = htobe32((MLX_QP_PM_MIGRATED << MLX_QP_PM_SHIFT) |
	    MLX_QP_ST_ETH | (MLX_QP_STATE_INIT << MLX_QP_STATE_SHIFT));
	qps->c.pd = htobe32(sc->sc_mlxc->sc_pd);
	qps->c.wq_params = htobe32(
	    ((fls(sizeof(struct mlx_send_wqe) - 1) - 4) << MLX_QP_SQ_STRIDE_SHIFT) |
	    (fls(MLX_ALLOC_TX_WQES - 1) << MLX_QP_SQ_SIZE_SHIFT) |
	    ((fls(sizeof(struct mlx_recv_wqe) - 1) - 4) << MLX_QP_RQ_STRIDE_SHIFT) |
	    (fls(MLX_ALLOC_RX_WQES - 1) << MLX_QP_RQ_SIZE_SHIFT) |
	    (MLX_MTU_ETH << MLX_QP_MTU_SHIFT) |
	    (MLX_QP_MSG_MAX << MLX_QP_MSG_MAX_SHIFT));
	printf("qp wq params: %x; send wq size %ld, stride %d, rsize %d, recv wq size %ld, stride %d, rsize %d\n", qps->c.wq_params, sizeof(struct mlx_send_wqe), fls(sizeof(struct mlx_send_wqe) - 1) - 4, fls(MLX_ALLOC_TX_WQES - 1), sizeof(struct mlx_recv_wqe), fls(sizeof(struct mlx_recv_wqe) - 1) - 4, fls(MLX_ALLOC_RX_WQES - 1));
	qps->c.usr_page = htobe32(qp->qp_uar);

	qps->c.primary.ack_timeout = 1;
	qps->c.primary.sched_queue = 0x83 | (sc->sc_port << 6);	/* what */
	
	qps->c.cqn_send = htobe32(sc->sc_tx_cq.cq_num);

	qps->c.page_offset_atomic = 0;
	qps->c.rra_max_pf = 0;

	qps->c.cqn_recv = htobe32(sc->sc_rx_cq.cq_num);

	qps->c.db_rec_addr_hi = htobe32(qp->qp_rx_db_addr >> 32);
	qps->c.db_rec_addr_lo = htobe32(qp->qp_rx_db_addr & 0xFFFFFFFFUL);

	qps->c.mtt_base_addr_hi_sz = htobe32(((qp->qp_mttr.mtt_addr >> 32) &
		0xFF) | ((PAGE_SHIFT - MLX_PAGE_SHIFT) << 24));
	qps->c.mtt_base_addr_lo = htobe32(qp->qp_mttr.mtt_addr &
	    0xFFFFFFFFUL);

	if (mlx_mbox_in(sc->sc_mlxc, qp->qp_num, 0, MLX_CMD_RST2INIT_QP, 1000) != 0) {
		printf("rst2init failed\n");
		return EIO;
	}
	if (mlx_mbox_in(sc->sc_mlxc, qp->qp_num, 0, MLX_CMD_INIT2RTR_QP, 1000) != 0) {
		printf("init2rtr failed\n");
		return EIO;
	}
	if (mlx_mbox_in(sc->sc_mlxc, qp->qp_num, 0, MLX_CMD_RTR2RTS_QP, 1000) != 0) {
		printf("rtr2rts failed\n");
		return EIO;
	}

	printf("whee\n");
	return 0;
}

void
mlx_destroy_qp(struct mlx_softc *sc, struct mlx_qp *qp)
{
	/* things */
}

int
mlx_up(struct mlx_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct mlxc_softc *csc = sc->sc_mlxc;
	struct mlx_set_port_rqp *port_rqp;
	struct mlx_set_port_gen *port_gen;
	int i, cq, uar, dbn, qpn, rv = 0;
	uint64_t *mactable;
	uint64_t mac = 0;

	cq = csc->sc_first_cq + (sc->sc_port * MLX_CQS_PER_PORT);
	uar = csc->sc_first_uar + sc->sc_port;
	dbn = sc->sc_port * MLX_DOORBELLS_PER_PORT;
	qpn = csc->sc_first_qp + (sc->sc_port * MLX_QPS_PER_PORT);
	printf("port %d cq %d qpn %d dbn %d uar %d\n", sc->sc_port, cq, qpn, dbn, uar);

	if (mlx_create_cq(csc, &sc->sc_tx_cq, cq++, uar, dbn++) != 0 ||
	    mlx_create_cq(csc, &sc->sc_rx_cq, cq++, uar, dbn++) != 0) {
		printf("%s: couldn't create completion queues\n",
		    DEVNAME(sc));
		goto destroy_cqs;
	}

	rv = mlx_prepare_qp(sc, &sc->sc_qp, qpn, dbn, uar);
	if (rv != 0)
		goto destroy_qp;

	rv = mlx_init_qp(sc, &sc->sc_qp);
	if (rv != 0)
		goto destroy_cqs;

	mlx_rx_fill(sc, &sc->sc_qp);
	mlx_arm_cq(sc->sc_mlxc, &sc->sc_rx_cq);
	mlx_arm_cq(sc->sc_mlxc, &sc->sc_tx_cq);

	/* set mac address table */
	mactable = (uint64_t *)MLX_DMA_KVA(sc->sc_mlxc->sc_mbox);
	memset(mactable, 0, MLX_MAC_TABLE_SIZE * sizeof(mac));
	for (i = 0; i < sizeof(sc->sc_ac.ac_enaddr); i++) {
		mac <<= 8;
		mac |= sc->sc_ac.ac_enaddr[sizeof(sc->sc_ac.ac_enaddr) - (i + 1)];
	}
	htobem64(&mactable[0], mac | (1ULL << 63));
	if (mlx_mbox_in(sc->sc_mlxc, MLX_SET_PORT_MAC | (sc->sc_port + 1), 1, MLX_CMD_SET_PORT,
	    10000) != 0) {
		printf("%s: set port mac list failed\n", DEVNAME(sc));
		goto destroy_qp;
	}

	/* disable multicast filter */
	if (mlx_cmd_imm(sc->sc_mlxc, sc->sc_port + 1, 1, MLX_CMD_SET_MCAST_FILTER, 1000, 0, NULL)) {
		printf("%s: clearing multicast filter failed\n", DEVNAME(sc));
		goto destroy_qp;
	}

	/* set default qp */
	port_rqp = (struct mlx_set_port_rqp *)MLX_DMA_KVA(sc->sc_mlxc->sc_mbox);
	memset(port_rqp, 0, sizeof(*port_rqp));
	port_rqp->base_qpn = htobe32(qpn);
	port_rqp->n_mac = sc->sc_max_macs;
	port_rqp->mac_miss_idx = htobe32(128);	/* what */
	port_rqp->intra_no_vlan = 0;
	port_rqp->no_vlan_idx = 0;		/* what */
	port_rqp->vlan_miss_idx = htobe32(1);	/* what */
	port_rqp->intra_miss = 0;
	port_rqp->promisc_qpn = htobe32(qpn | (1 << 31));	/* enable promisc? */
	port_rqp->def_mcast_qpn = htobe32(qpn | (1 << 30));	/* receive all mcast */
	if (mlx_mbox_in(sc->sc_mlxc, MLX_SET_PORT_RQP | (sc->sc_port + 1), 1, MLX_CMD_SET_PORT,
	    10000) != 0) {
		printf("%s: set port rqp failed\n", DEVNAME(sc));
		goto destroy_qp;
	}

	/* set port generic things */
	port_gen = (struct mlx_set_port_gen *)MLX_DMA_KVA(sc->sc_mlxc->sc_mbox);
	memset(port_gen, 0, sizeof(*port_gen));
	port_gen->flags = 7; // MLX_PORT_GEN_FLAG_ALL_VALID;
	port_gen->mtu = htobe16(MCLBYTES);		/* actual mtu */
	port_gen->pptx = 1 << 7;
	port_gen->pfctx = 0;
	port_gen->pprx = 1 << 7;
	port_gen->pfcrx = 0;
	if (mlx_mbox_in(sc->sc_mlxc, MLX_SET_PORT_GEN | (sc->sc_port + 1), 1, MLX_CMD_SET_PORT,
	    10000) != 0) {
		printf("%s: set port gen failed\n", DEVNAME(sc));
		goto destroy_qp;
	}

	if (mlx_cmd_imm(sc->sc_mlxc, sc->sc_port + 1, 0, MLX_CMD_INIT_PORT, 1000, 0, 0) != 0) {
		printf("%s: init port failed\n", DEVNAME(sc));
		goto destroy_qp;
	}

	SET(ifp->if_flags, IFF_RUNNING);
	return 0;

destroy_qp:
	mlx_destroy_qp(sc, &sc->sc_qp);
destroy_cqs:
	mlx_destroy_cq(csc, &sc->sc_tx_cq);
	mlx_destroy_cq(csc, &sc->sc_rx_cq);

	return rv;
}

void
mlx_down(struct mlx_softc *sc)
{
	mlx_destroy_cq(sc->sc_mlxc, &sc->sc_tx_cq);
	mlx_destroy_cq(sc->sc_mlxc, &sc->sc_rx_cq);
}

int
mlx_fill(struct mlx_softc *sc)
{
	return 0;
}

struct mlx_dmamem *
mlx_dmamem_alloc(struct mlxc_softc *sc, size_t size, size_t align)
{
	struct mlx_dmamem *m;
	int nsegs;

	m = malloc(sizeof(*m), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (m == NULL)
		return NULL;

	m->mxm_size = size;
	if (bus_dmamap_create(sc->sc_dmat, size, 1, size, 0,
	    BUS_DMA_NOWAIT | BUS_DMA_ALLOCNOW, &m->mxm_map) != 0)
		goto mxmfree;

	if (bus_dmamem_alloc(sc->sc_dmat, size, align, 0, &m->mxm_seg, 1,
	    &nsegs, BUS_DMA_NOWAIT | BUS_DMA_ZERO) != 0)
		goto destroy;

	if (bus_dmamem_map(sc->sc_dmat, &m->mxm_seg, nsegs, size, &m->mxm_kva,
	    BUS_DMA_NOWAIT) != 0)
		goto free;

	if (bus_dmamap_load(sc->sc_dmat, m->mxm_map, m->mxm_kva, size, NULL,
	    BUS_DMA_NOWAIT) != 0)
		goto unmap;

	return m;
unmap:
	bus_dmamem_unmap(sc->sc_dmat, m->mxm_kva, m->mxm_size);
free:
	bus_dmamem_free(sc->sc_dmat, &m->mxm_seg, 1);
destroy:
	bus_dmamap_destroy(sc->sc_dmat, m->mxm_map);
mxmfree:
	free(m, M_DEVBUF, sizeof *m);
	return NULL;
}

void
mlx_dmamem_free(struct mlxc_softc *sc, struct mlx_dmamem *m)
{
	bus_dmamap_unload(sc->sc_dmat, m->mxm_map);
	bus_dmamem_unmap(sc->sc_dmat, m->mxm_kva, m->mxm_size);
	bus_dmamem_free(sc->sc_dmat, &m->mxm_seg, 1);
	bus_dmamap_destroy(sc->sc_dmat, m->mxm_map);
	free(m, M_DEVBUF, sizeof *m);
}

int
mlx_pending(struct mlxc_softc *sc)
{
	uint32_t status;

	status = betoh32(bus_space_read_raw_4(sc->sc_memt_cfg,
	    sc->sc_memh_cfg, MLX_HCR_BASE + MLX_HCR_STATUS));
	return (status & MLX_HCR_GO) || ((status & (1 << MLX_HCR_T_SHIFT)) ==
	    (sc->sc_cmd_toggle << MLX_HCR_T_SHIFT));
}

void
mlx_cmd(struct mlxc_softc *sc, uint64_t in_param, uint64_t out_param,
    uint32_t in_mod, uint8_t op_mod, uint16_t op, uint16_t token, int event)
{
	uint32_t cmd;
	int o = MLX_HCR_BASE;

	/* wait until idle?  or just fail if already busy? */

	bus_space_write_raw_4(sc->sc_memt_cfg, sc->sc_memh_cfg, o,
	    htobe32(in_param >> 32));
	bus_space_write_raw_4(sc->sc_memt_cfg, sc->sc_memh_cfg, o + 4,
	    htobe32(in_param & 0xFFFFFFFFUL));
	bus_space_write_raw_4(sc->sc_memt_cfg, sc->sc_memh_cfg, o + 8,
	    htobe32(in_mod));
	bus_space_write_raw_4(sc->sc_memt_cfg, sc->sc_memh_cfg, o + 12,
	    htobe32(out_param >> 32));
	bus_space_write_raw_4(sc->sc_memt_cfg, sc->sc_memh_cfg, o + 16,
	    htobe32(out_param & 0xFFFFFFFFUL));
	bus_space_write_raw_4(sc->sc_memt_cfg, sc->sc_memh_cfg, o + 20,
	    htobe32(token << 16));
	bus_space_barrier(sc->sc_memt_cfg, sc->sc_memh_cfg, o, 24,
	    BUS_SPACE_BARRIER_WRITE);

	cmd = MLX_HCR_GO | (sc->sc_cmd_toggle << MLX_HCR_T_SHIFT) |
	    (event << MLX_HCR_E_SHIFT) | (op_mod << MLX_HCR_OPMOD_SHIFT) | op;
	bus_space_write_raw_4(sc->sc_memt_cfg, sc->sc_memh_cfg, o + 24,
	    htobe32(cmd));
	bus_space_barrier(sc->sc_memt_cfg, sc->sc_memh_cfg, o + 24, 4,
	    BUS_SPACE_BARRIER_READ | BUS_SPACE_BARRIER_WRITE);
	sc->sc_cmd_toggle = sc->sc_cmd_toggle ^ 1;
}

int
mlx_poll_cmd(struct mlxc_softc *sc, int timeout)
{
	uint32_t status;
	int otimeout = timeout;
	while (--timeout) {
		if (mlx_pending(sc) == 0)
			break;

		delay(1000);
	}

	if (timeout == 0) {
		printf("cmd timed out after %d\n", otimeout);
		return -1;
	}

	status = betoh32(bus_space_read_raw_4(sc->sc_memt_cfg,
	    sc->sc_memh_cfg, MLX_HCR_BASE + MLX_HCR_STATUS)) >> 24;
	if (status != 0)
		printf("cmd took %d cycles, status %x\n", otimeout - timeout, status);
	else
		delay(10);
	return status;
}

int
mlx_mbox_in(struct mlxc_softc *sc, uint32_t in_mod, uint8_t op_mod,
    uint16_t op, int timeout)
{
	int rv;

	bus_dmamap_sync(sc->sc_dmat, sc->sc_mbox->mxm_map, 0, MLX_MBOX_SIZE,
	    BUS_DMASYNC_PREWRITE);
	mlx_cmd(sc, MLX_DMA_DVA(sc->sc_mbox), 0, in_mod, op_mod, op,
	    MLX_CMD_POLL_TOKEN, 0);
	rv = mlx_poll_cmd(sc, timeout);
	bus_dmamap_sync(sc->sc_dmat, sc->sc_mbox->mxm_map, 0, MLX_MBOX_SIZE,
	    BUS_DMASYNC_POSTWRITE);

	return rv;
}

int
mlx_mbox_out(struct mlxc_softc *sc, uint32_t in_mod, uint8_t op_mod,
    uint16_t op, int timeout)
{
	int rv;

	bus_dmamap_sync(sc->sc_dmat, sc->sc_mbox->mxm_map, 0, MLX_MBOX_SIZE,
	    BUS_DMASYNC_PREREAD);
	mlx_cmd(sc, 0, MLX_DMA_DVA(sc->sc_mbox), in_mod, op_mod, op,
	    MLX_CMD_POLL_TOKEN, 0);
	rv = mlx_poll_cmd(sc, timeout);
	if (rv == 0) {
		bus_dmamap_sync(sc->sc_dmat, sc->sc_mbox->mxm_map, 0,
		    MLX_MBOX_SIZE, BUS_DMASYNC_POSTREAD);
	}
	return rv;
}

int
mlx_cmd_imm(struct mlxc_softc *sc, uint32_t in_mod, uint8_t op_mod,
    uint16_t op, int timeout, uint64_t in, uint64_t *out)
{
	int rv;

	mlx_cmd(sc, in, 0, in_mod, op_mod, op, MLX_CMD_POLL_TOKEN, 0);
	rv = mlx_poll_cmd(sc, timeout);
	if (rv == 0 && out != NULL) {
		uint64_t o;

		o = betoh32(bus_space_read_raw_4(sc->sc_memt_cfg,
		    sc->sc_memh_cfg, MLX_HCR_BASE + 12));
		o <<= 32;
		o |= betoh32(bus_space_read_raw_4(sc->sc_memt_cfg,
		    sc->sc_memh_cfg, MLX_HCR_BASE + 16));
		*out = o;
	}
	return rv;
}

struct mlx_eq_entry *
mlx_next_event(struct mlxc_softc *sc)
{
	struct mlx_eq_entry *eqe;
	int index;
	uint32_t own;

	index = sc->sc_eqc_cons & (MLX_ALLOC_EQES - 1);
	eqe = (struct mlx_eq_entry *)MLX_DMA_KVA(sc->sc_eqe) + index;

	own = (sc->sc_eqc_cons & MLX_ALLOC_EQES) ? MLX_QE_OWNER : 0;

	bus_dmamap_sync(sc->sc_dmat, sc->sc_eqe->mxm_map,
	    index * sizeof(struct mlx_eq_entry), sizeof(struct mlx_eq_entry),
	    BUS_DMASYNC_POSTREAD);
	if ((betoh32(eqe->owner) & MLX_QE_OWNER) ^ own) {
#if 0
		if (own) {
			printf("%d: im not owned (%x, %d, %d)\n", sc->sc_eqc_cons,
			    betoh32(eqe->owner), (sc->sc_eqc_cons & MLX_ALLOC_EQES),
			    own);
			dump_stuff(eqe, sizeof(*eqe));
		}
#endif
		return NULL;
	}

	sc->sc_eqc_cons++;
	return eqe;
}

int
mlx_buf_fill(struct mlx_softc *sc, struct mlx_slot *ms)
{
	struct mbuf *m;
	int rv;

	m = MCLGETL(NULL, M_DONTWAIT, MCLBYTES);
	if (m == NULL)
		return ENOMEM;

	m->m_len = m->m_pkthdr.len = MCLBYTES;
	memset(mtod(m, caddr_t), 0, MCLBYTES);

	rv = bus_dmamap_load_mbuf(sc->sc_mlxc->sc_dmat, ms->ms_map, m,
	    BUS_DMA_NOWAIT);
	if (rv != 0) {
		m_freem(m);
		return rv;
	}

	bus_dmamap_sync(sc->sc_mlxc->sc_dmat, ms->ms_map, 0,
	    ms->ms_map->dm_mapsize, BUS_DMASYNC_PREREAD);
	ms->ms_m = m;
	return 0;
}

int
mlx_rx_fill_slots(struct mlx_softc *sc, struct mlx_qp *qp, u_int slots)
{
	struct mlxc_softc *mlxc;
	struct mlx_slot *ms;
	struct mlx_recv_wqe *wqe;
	u_int p, first, fills;
	uint64_t addr;

	mlxc = sc->sc_mlxc;
	first = p = (qp->qp_rx_prod & (MLX_ALLOC_RX_WQES - 1));
	for (fills = 0; fills < slots; fills++) {
		ms = &qp->qp_rx_slots[p];
		if (mlx_buf_fill(sc, ms) != 0)
			break;

		if (++p >= MLX_ALLOC_RX_WQES)
			p = 0;

		wqe = &qp->qp_recv_wqe[p];
		wqe->segs[0].size = htobe32(ms->ms_m->m_len);
		wqe->segs[0].lkey = htobe32(sc->sc_mlxc->sc_mpt_key);
		addr = ms->ms_map->dm_segs[0].ds_addr;
		wqe->segs[0].local_addr_hi = htobe32(addr >> 32);
		wqe->segs[0].local_addr_lo = htobe32(addr & 0xFFFFFFFFUL);

		wqe->segs[1].size = 0;
		wqe->segs[1].local_addr_hi = 0;
		wqe->segs[1].local_addr_lo = 0;
		wqe->segs[1].lkey = htobe32(MLX_INVALID_LKEY);
		dump_stuff(wqe, sizeof(*wqe));

		*qp->qp_rx_doorbell = htobe32(qp->qp_rx_prod_db & 0xffff);
		qp->qp_rx_prod_db++;
	}

	qp->qp_rx_prod = p;

	printf("filled %d/%d slots [%d:%d]; db %d\n", fills, slots, first, p, qp->qp_rx_prod_db);
	return slots - fills;
}

int
mlx_rx_fill(struct mlx_softc *sc, struct mlx_qp *qp)
{
	u_int slots;

	slots = if_rxr_get(&qp->qp_rxr, MLX_ALLOC_RX_WQES);
	if (slots == 0)
		return 1;

	slots = mlx_rx_fill_slots(sc, qp, slots);
	if (slots > 0)
		if_rxr_put(&qp->qp_rxr, slots);

	return 0;
}

struct mlx_cq_entry *
mlx_next_cq_entry(struct mlx_softc *sc, struct mlx_cq *cq)
{
	int index;
	struct mlx_cq_entry *cqe;

	index = cq->cq_cons & (MLX_ALLOC_CQES - 1);
	cqe = ((struct mlx_cq_entry *)MLX_DMA_KVA(cq->cq_entries)) + index;
	if ((cqe->owner_sr_op & MLX_QE_OWNER) ==
	    ((cq->cq_cons & MLX_ALLOC_CQES) ? MLX_QE_OWNER : 0)) {
		printf("good cq entry %d\n", index);
		dump_stuff(cqe, sizeof(*cqe));
		cq->cq_cons++;
		return cqe;
	}

	printf("boring cq entry %d?\n", index);
	dump_stuff(cqe, sizeof(*cqe));
	return NULL;
}

void
mlx_process_rx_cq(struct mlx_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct mlx_cq *cq;
	struct mlx_cq_entry *cqe;
	struct mlx_slot *ms;
	struct mlx_qp *qp;
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();
	int rxd;

	cq = &sc->sc_rx_cq;

	cqe = mlx_next_cq_entry(sc, cq);
	rxd = 0;
	while (cqe != NULL) {
		/* in theory we could have multiple qps here,
		 * so we'd have to look up the qp to process..
		 */
		qp = &sc->sc_qp;
		ms = &qp->qp_rx_slots[qp->qp_rx_cons];
		qp->qp_rx_cons++;
		if (qp->qp_rx_cons == MLX_ALLOC_RX_WQES)
			qp->qp_rx_cons = 0;

		bus_dmamap_sync(sc->sc_mlxc->sc_dmat, ms->ms_map, 0,
		    ms->ms_map->dm_mapsize, BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(sc->sc_mlxc->sc_dmat, ms->ms_map);

		ml_enqueue(&ml, ms->ms_m);
		rxd++;

		cqe = mlx_next_cq_entry(sc, cq);
	}

	mlx_arm_cq(sc->sc_mlxc, cq);

	if_rxr_put(&sc->sc_qp.qp_rxr, rxd);
	mlx_rx_fill(sc, &sc->sc_qp);
	if_input(ifp, &ml);
}

void
mlx_process_tx_cq(struct mlx_softc *sc)
{
	struct mlx_cq *cq;
	struct mlx_cq_entry *cqe;

	cq = &sc->sc_rx_cq;

	cqe = mlx_next_cq_entry(sc, cq);
	while (cqe != NULL) {
		printf("tx completion:\n");
		dump_stuff(cqe, sizeof(*cqe));
	}

	mlx_arm_cq(sc->sc_mlxc, cq);
}

void
mlx_link_up(struct mlx_softc *sc)
{
	struct mlx_query_port *qp;
	sc->sc_active_media = IFM_ETHER;

	qp = (struct mlx_query_port *)MLX_DMA_KVA(sc->sc_mlxc->sc_mbox);
	memset(qp, 0, sizeof(*qp));
	if (mlx_mbox_out(sc->sc_mlxc, sc->sc_port + 1, 0, MLX_CMD_QUERY_PORT, 1000) != 0) {
		printf("query port failed\n");
		return;
	}

	printf("%s: link_up %d, autoneg %d, link speed %d, xcvr %d\n", DEVNAME(sc), qp->link_up, qp->autoneg, qp->link_speed, qp->xcvr);
	sc->sc_active_media |= IFM_FDX;
	if (qp->link_up & 0x80) {
		switch (qp->link_speed) {
		case 0:
		case 1:
			if (qp->xcvr > 0 && qp->xcvr < 0xc)
				sc->sc_active_media |= IFM_10G_SR;
			else if (qp->xcvr == 0x80 || qp->xcvr == 0)
				sc->sc_active_media |= IFM_10G_SFP_CU;
			break;
		case 64:
			sc->sc_active_media |= IFM_40G_CR4;
			break;
		}
	}
}

void
mlx_link_down(struct mlx_softc *sc)
{
	printf("%s: link down\n", DEVNAME(sc));
	sc->sc_active_media = IFM_ETHER;
}

int
mlx_intr(void *arg)
{
	struct mlxc_softc *sc = (struct mlxc_softc *)arg;
	struct mlx_softc *psc;
	struct mlx_eq_entry *eqe;
	int consumed = 0;
	int cqn;
	uint32_t port;

	bus_space_write_raw_8(sc->sc_memt_cfg, sc->sc_memh_cfg,
	    sc->sc_clr_offset, sc->sc_clr_int);

	eqe = mlx_next_event(sc);
	while (eqe != NULL) {
		consumed++;

		switch (eqe->type) {
		case MLX_EVENT_TYPE_COMP:
			cqn = betoh32(eqe->data[0]);
			port = (cqn - sc->sc_first_cq) / MLX_CQS_PER_PORT;
			printf("completion event %d/port %d/%s\n", cqn, port,
			   (cqn % MLX_CQS_PER_PORT) == MLX_CQ_TX ? "tx" : "rx");
			if ((cqn % MLX_CQS_PER_PORT) == MLX_CQ_TX) {
				mlx_process_tx_cq(sc->sc_ports[port]);
			} else {
				mlx_process_rx_cq(sc->sc_ports[port]);
			}
			break;

		case MLX_EVENT_TYPE_PORT:
			printf("port change event\n");
			port = betoh32(eqe->data[2]) >> 28;
			psc = sc->sc_ports[port - 1];

			if (eqe->subtype == 4) {
				mlx_link_up(psc);
			} else {
				mlx_link_down(psc);
			}
			break;

		case MLX_EVENT_TYPE_CMD:
			printf("command event\n");
			/* wakeup etc. */
			break;

		default:
			printf("event type %x\n", eqe->type);
			break;
		}

		eqe = mlx_next_event(sc);

		bus_space_write_raw_4(sc->sc_memt_uar, sc->sc_memh_uar,
		   sc->sc_eqc_db, htobe32((1 << 31) | sc->sc_eqc_cons));
		membar_sync();
	}
	if (consumed > 0)
		printf("done: %d\n", sc->sc_eqc_cons);
	
	return 1;
}
