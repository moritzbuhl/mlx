/*	$OpenBSD$	*/

/*
 * Copyright (c) 2016 Jonathan Matthew <jmatthew@openbsd.org>
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

/* PCI BARs */
#define MLX_PCI_CONFIG_BAR	0x10
#define MLX_PCI_UAR_BAR		0x18

/* config registers */
#define MLX_HCR_BASE		0x80680
#define MLX_HCR_SIZE		0x1c

#define MLX_RESET_BASE		0xf0010
#define MLX_RESET_MAGIC		0x01000000UL

#define MLX_MBOX_SIZE		4096
#define MLX_PAGE_SHIFT		12
#define MLX_PAGE_SIZE		(1 << MLX_PAGE_SHIFT)
#define MLX_FWAREA_CHUNK_SHIFT	16
#define MLX_FWAREA_CHUNK	(1 << MLX_FWAREA_CHUNK_SHIFT)

#define MLX_CMPT_BLOCK_SIZE	(1 << 24)

#define MLX_CMD_POLL_TOKEN	0xffff

#define MLX_CMD_INTF_REV	3
#define MLX_INIT_VERSION	2
#define MLX_INIT_FLAGS		0

#define MLX_HCR_IN_PARAM	0x00
#define MLX_HCR_IN_MODIFIER	0x08
#define MLX_HCR_OUT_PARAM	0x0c
#define MLX_HCR_TOKEN		0x14
#define MLX_HCR_STATUS		0x18

#define MLX_HCR_OPMOD_SHIFT	12
#define MLX_HCR_T_SHIFT		21
#define MLX_HCR_E_SHIFT		22
#define MLX_HCR_GO		(1 << 23)

/* UARs */
#define MLX_EQ_UAR_OFFSET	0x800
#define MLX_EQ_UAR_SIZE		8
#define MLX_EQS_PER_UAR		4

#define MLX_EQ_UARS		128

#define MLX_UAR_SEND_DOORBELL	0x14
#define MLX_UAR_CQ_DOORBELL	0x20

#define MLX_MAC_TABLE_SIZE	128
#define MLX_VLAN_TABLE_SIZE	128

/* commands */
#define MLX_CMD_QUERY_DEV_CAP	0x003
#define MLX_CMD_QUERY_FW	0x004
#define MLX_CMD_QUERY_ADAPTER	0x006
#define MLX_CMD_INIT_HCA	0x007
#define MLX_CMD_CLOSE_HCA	0x008
#define MLX_CMD_INIT_PORT	0x009
#define MLX_CMD_CLOSE_PORT	0x00a
#define MLX_CMD_QUERY_HCA	0x00b
#define MLX_CMD_SET_PORT	0x00c
#define MLX_CMD_SW2HW_MPT	0x00d
#define MLX_CMD_READ_MTT	0x010
#define MLX_CMD_WRITE_MTT	0x011
#define MLX_CMD_MAP_EQ		0x012
#define MLX_CMD_SW2HW_EQ	0x013
#define MLX_CMD_HW2SW_EQ	0x014
#define MLX_CMD_QUERY_EQ	0x015
#define MLX_CMD_SW2HW_CQ	0x016
#define MLX_CMD_RST2INIT_QP	0x019
#define MLX_CMD_INIT2RTR_QP	0x01a
#define MLX_CMD_RTR2RTS_QP	0x01b
#define MLX_CMD_RTS2RTS_QP	0x01c
#define MLX_CMD_2RTS_QP		0x021
#define MLX_CMD_QUERY_QP	0x022
#define MLX_CMD_CONF_SPECIAL_QP	0x023
#define MLX_CMD_NOP		0x031
#define MLX_CMD_MOD_STAT_CFG	0x034
#define MLX_CMD_SW2HW_SRQ	0x035
#define MLX_CMD_QUERY_PORT	0x043
#define MLX_CMD_SET_MCAST_FILTER 0x048

#define MLX_CMD_RUN_FW		0xff6
#define MLX_CMD_UNMAP_ICM	0xff9
#define MLX_CMD_MAP_ICM		0xffa
#define MLX_CMD_UNMAP_ICM_AUX	0xffb
#define MLX_CMD_MAP_ICM_AUX	0xffc
#define MLX_CMD_SET_ICM_SIZE	0xffd
#define MLX_CMD_MAP_FA		0xfff
#define MLX_CMD_UNMAP_FA	0xffe

/* event types */
#define MLX_EVENT_TYPE_COMP	0x00
#define MLX_EVENT_TYPE_PORT	0x09
#define MLX_EVENT_TYPE_CMD	0x0a

#define MLX_QE_OWNER		(1 << 7)

#define MLX_INVALID_LKEY	0x00000100UL

/* sparc64 will make me cry */
struct mlx_query_fw {
	uint16_t	fw_pages;
	uint16_t	fw_rev_major;

	uint16_t	fw_rev_subminor;
	uint16_t	fw_rev_minor;

	uint8_t		fw_ppf_id;
	uint8_t		reserved1;
	uint16_t	cmd_interface_rev;

	uint8_t		debug_trace;
	uint16_t	reserved2;
	uint8_t		log_max_cmd;

	uint8_t		fw_hour;
	uint8_t		fw_minutes;
	uint8_t		fw_seconds;
	uint8_t		ccq;

	uint16_t	fw_year;
	uint8_t		fw_month;
	uint8_t		fw_day;

	uint64_t	reserved3;

	uint32_t	clr_int_hi;
	uint32_t	clr_int_lo;
	uint8_t		clr_int_bar;
	uint8_t		reserved4[3];

	uint32_t	reserved5;

	uint32_t	error_buf_hi;
	uint32_t	error_buf_lo;
	uint32_t	error_buf_size;
	uint32_t	error_buf_bar;

	uint32_t	comm_hi;
	uint32_t	comm_lo;
	uint8_t		comm_bar;
	uint8_t		reserved6[3];
} __packed;

struct mlx_map_mem {
	uint32_t	va_h;
	uint32_t	va_l;
	uint32_t	pa_h;
	uint32_t	pa_l_size;
} __packed;

struct mlx_mod_stat_cfg {
	uint16_t	reserved1;
	uint8_t		pg_sz_m;
	uint8_t		pg_sz;
	uint32_t	reserved2[63];
} __packed;

struct mlx_query_dev_cap {
	uint32_t	reserved1[4];			// 0 - 3

	uint8_t		log_max_srq_sz;
	uint8_t		log_max_qp_sz;
	uint8_t		log_rsvd_qp;
	uint8_t		log_max_qp;			// 4

	uint16_t	log_srqs;
	uint8_t		num_rsvd_scqs;
	uint8_t		log_max_scqs;			// 5

	uint8_t		num_rsvd_eqs;
	uint8_t		log_max_cq_sz;
	uint8_t		log_rsvd_cqs;
	uint8_t		log_max_cqs;			// 6

	uint8_t		log_max_eq_sz;
	uint8_t		log_max_d_mpts;
	uint8_t		log_rsvd_eqs;
	uint8_t		log_max_eqs;			// 7

	uint8_t		log_rsvd_mtts;
	uint8_t		log_max_mrw_sz;
	uint8_t		log_rsvd_mrws;
	uint8_t		log_max_mtts;			// 8

	uint32_t	reserved2;			// 9

	uint16_t	log_max_ra_req_qp;
	uint16_t	log_max_ra_res_qp;		// 10

	uint32_t	log_max_ra_res_global;		// 11

	uint32_t	rsz_srq;			// 12

	uint16_t	port_flags;
	uint8_t		pci_pf_num;
	uint8_t		num_ports;			// 13

	uint8_t		log_max_msg;
	uint8_t		log_drain_size;
	uint8_t		log_ethtype;
	uint8_t		log_max_gid;			// 14

	uint16_t	stat_rate_support;
	uint16_t	log_max_pkey;			// 15

	uint32_t	flags;				// 16
	uint32_t	flags2;				// 17

	uint16_t	uar_sz_rsvd;
	uint8_t		reserved3;
	uint8_t		log_pg_sz;			// 18

	uint16_t	log_bf_reg_size;
	uint8_t		log_max_bf_regs_per_page;
	uint8_t		log_max_bf_pages;		// 19

	uint8_t		reserved4;
	uint8_t		max_sg_sq;
	uint16_t	max_desc_sz_sq;			// 20

	uint16_t	max_sg_rq;
	uint16_t	max_desc_sz_rq;			// 21

	uint8_t		fexch_base_qp;
	uint16_t	fcp_ud_base;
	uint8_t		fexch_base_mpt;			// 22

	uint32_t	reserved5;			// 23

	uint8_t		reserved6;
	uint8_t		log_max_qp_mcg;
	uint8_t		num_rsvd_mcgs;
	uint8_t		log_max_mcg;			// 24

	uint8_t		num_rsvd_pds;
	uint8_t		log_max_pd;
	uint8_t		num_rsvd_srcds;
	uint8_t		log_max_srcds;			// 25

	uint32_t	reserved7[6];			// 26 27 28 29 30 31

	uint16_t	rdmadc_entry_sz;
	uint16_t	qpc_entry_sz;			// 32

	uint16_t	aux_entry_sz;
	uint16_t	altc_entry_sz;			// 33

	uint16_t	eqc_entry_sz;
	uint16_t	cqc_entry_sz;			// 34

	uint16_t	srq_entry_sz;
	uint16_t	c_mpt_entry_sz;			// 35

	uint16_t	mtt_entry_sz;
	uint16_t	d_mpt_entry_sz;			// 36

	uint32_t	flags3;				// 37

	uint32_t	resd_lkey;			// 38

	uint32_t	reserved8;			// 39

	uint32_t	max_icm_size_h;			// 40
	uint32_t	max_icm_size_l;			// 41

	uint32_t	reserved9[22];
} __packed;

#define MLX_PORT_CAP_IB		(1 << 24)
#define MLX_PORT_CAP_ETH	(1 << 25)
#define MLX_PORT_CAP_LINK	(1 << 31)

struct mlx_port_cap {
	uint32_t	mtus;

	uint8_t		ib_link_speed;
	uint8_t		eth_link_speed;
	uint8_t		ib_port_width;
	uint8_t		log_max_pkey_gid;

	uint16_t	reserved1;
	uint8_t		log_max_mac_vlan;
	uint8_t		max_vl_ib;

	uint32_t	reserved2;

	uint16_t	reserved3;
	uint16_t	mac_hi;

	uint32_t	mac_lo;

	uint32_t	vendor_xcvr;

	uint16_t	wavelength;
	uint16_t	reserved4;

	uint32_t	xcvr_code_hi;
	uint32_t	xcvr_code_lo;

	uint32_t	reserved5[6];
} __packed;

struct mlx_init_hca {
	uint8_t		version;
	uint8_t		reserved1[3];		// 0

	uint32_t	reserved2[2];		// 1 2

	uint16_t	hca_core_clock;
	uint8_t		cacheline_sz;
	uint8_t		reserved3;		// 3

	uint32_t	router;			// 4

	uint32_t	flags;			// 5

	uint32_t	reserved4[2];		// 6 7

	/* qpcbaseaddr */
	uint32_t	qreserved1[4];		// 8 9 10 11

	uint32_t	qpc_base_addr_hi;	// 12
	uint32_t	qpc_base_addr_lo_count;	// 13

	uint32_t	qreserved2[4];		// 14 15 16 17

	uint32_t	srqc_base_addr_hi;	// 18
	uint32_t	srqc_base_addr_lo_count; // 19

	uint32_t	cqc_base_addr_hi;	// 20
	uint32_t	cqc_base_addr_lo_count;	// 21

	uint32_t	qreserved3[2];		// 22 23

	uint32_t	altc_base_addr_hi;	// 24
	uint32_t	altc_base_addr_lo;	// 25

	uint32_t	qreserved4[2];		// 26 27

	uint32_t	auxc_base_addr_hi;	// 28
	uint32_t	auxc_base_addr_lo;	// 29

	uint32_t	qreserved5[2];		// 30 31

	uint32_t	eqc_base_addr_hi;	// 32
	uint32_t	eqc_base_addr_lo_count;	// 33

	uint32_t	qreserved6[2];		// 34 35

	uint32_t	rdmardc_base_addr_hi;	// 36
	uint32_t	rdmardc_base_addr_lo;	// 37

	uint32_t	qreserved7[2];		// 38 39

	uint32_t	reserved5[8];		// 40 41 42 43 44 45 46 47

	/* multicastparam */
	uint32_t	mc_base_addr_hi;	// 48
	uint32_t	mc_base_addr_lo;	// 49

	uint32_t	mreserved1[2];		// 50 51

	uint32_t	mc_table_entry_sz;	// 52
	uint32_t	mc_table_hash_sz;	// 53

	uint16_t	mc_hash_steering;
	uint16_t	mc_table_sz;		// 54

	uint32_t	mreserved2;		// 55

	uint32_t	reserved6[4];		// 56 57 58 59

	/* tptparams */
	uint32_t	dmpt_base_addr_hi;	// 60
	uint32_t	dmpt_base_addr_lo;	// 61

	uint16_t	mw_enable;
	uint8_t		pfto;
	uint8_t		log_dmpt_sz;		// 62

	uint32_t	treserved1;		// 63

	uint32_t	mtt_base_addr_hi;	// 64
	uint32_t	mtt_base_addr_lo;	// 65

	uint32_t	cmpt_base_addr_hi;	// 66
	uint32_t	cmpt_base_addr_lo;	// 67

	uint32_t	reserved7[4];		// 68 69 70 71

	/* uarparams */
	uint32_t	ureserved1[2];		// 72 73
	
	uint16_t	ureserved2;
	uint8_t		log_max_uars;
	uint8_t		uar_page_sz;		// 74

	uint32_t	ureserved3[5];		// 75

	uint32_t	reserved8[48];
} __packed;

struct mlx_init_port {
	uint8_t		vl_cap;
	uint8_t		port_width_cap;
	uint16_t	g0_ng_sig;

	uint16_t	max_gid;
	uint16_t	mtu;

	uint16_t	max_pkey;
	uint16_t	reserved1;

	uint32_t	reserved2;

	uint32_t	guid0_hi;
	uint32_t	guid0_lo;

	uint32_t	node_guid_hi;
	uint32_t	node_guid_lo;

	uint32_t	system_image_guid_hi;
	uint32_t	system_image_guid_lo;

	uint32_t	reserved3[54];
} __packed;

struct mlx_query_adapter {
	uint32_t	reserved1[4];

	uint8_t		inta_pin;
	uint8_t		reserved2[3];

	uint32_t	reserved3[3];

	uint32_t	vsd[56];
} __packed;

struct mlx_mcg_entry {
	uint32_t	next_mcg;

	uint32_t	members;

	uint32_t	reserved1[2];

	uint32_t	gid3;
	uint32_t	gid2;
	uint32_t	gid1;
	uint32_t	gid0;

	uint32_t	qp[8];
} __packed;

#define MLX_MPT_FLAG_REG_WIN	(1 << 8)
#define MLX_MPT_FLAG_PA		(1 << 9)
#define MLX_MPT_FLAG_LR		(1 << 10)
#define MLX_MPT_FLAG_LW		(1 << 11)
#define MLX_MPT_FLAG_RR		(1 << 12)
#define MLX_MPT_FLAG_RW		(1 << 13)
#define MLX_MPT_FLAG_ATOMIC	(1 << 14)
#define MLX_MPT_FLAG_MIO	(1 << 17)

#define MLX_MPT_FLAG_SW_OWNS	(0xfUL << 28)

#define MLX_MPT_PD_FLAG_EN_INV	(3 << 24)

#define MLX_MKEY_PREFIX	0x77000000UL

#define MLX_MPT_LEN64	(1 << 9)

struct mlx_mpt {
	uint32_t	flags;

	uint32_t	qpn;

	uint32_t	mem_key;

	uint32_t	pd_flags2;

	uint32_t	start_addr_hi;
	uint32_t	start_addr_lo;

	uint32_t	len_hi;
	uint32_t	len_lo;

	uint32_t	lkey;

	uint32_t	win_cnt;

	uint32_t	mtt_rep;

	uint32_t	mtt_addr_hi;
	uint32_t	mtt_addr_lo;

	uint32_t	mtt_size;

	uint32_t	entity_size;

	uint32_t	mtt_fbo;
} __packed;

#define MLX_MTT_PRESENT	1

struct mlx_mtt {
	uint32_t	ptag_hi;
	uint32_t	ptag_lo;
} __packed;

struct mlx_write_mtt {
	uint32_t	mtt_base_addr_hi;
	uint32_t	mtt_base_addr_lo;
	uint32_t	reserved[2];
	uint32_t	ptag_hi;
	uint32_t	ptag_lo;
} __packed;

#define MLX_EQC_STATUS_WRITE_FAIL	(0xa << 28)

#define MLX_EQC_STATUS_ARMED		(0x9 << 8)
#define MLX_EQC_STATUS_FIRED		(0xa << 8)
#define MLX_EQC_STATUS_ALWAYS_ARMED	(0xb << 8)

#define MLX_EQC_FLAG_OI			(1 << 17)
#define MLX_EQC_FLAG_EC			(1 << 18)

struct mlx_eq_context {
	uint32_t	status;

	uint32_t	reserved1;

	uint32_t	page_offset;

	uint32_t	log_eq_size;

	uint16_t	eq_period;
	uint16_t	eq_max_count;

	uint32_t	intr;

	uint32_t	mtt_base_addr_hi_sz;

	uint32_t	mtt_base_addr_lo;

	uint32_t	reserved2[2];

	uint32_t	cons;

	uint32_t	prod;

	uint32_t	reserved3[4];
} __packed;


struct mlx_eq_entry {
	uint8_t		reserved1;
	uint8_t		type;
	uint8_t		reserved2;
	uint8_t		subtype;

	uint32_t	data[6];
	
	uint32_t	owner;
} __packed;

struct mlx_cq_context {
	uint32_t	status;

	uint32_t	reserved1;

	uint32_t	page_offset;

	uint32_t	logsize_uarpage;

	uint16_t	cq_period;
	uint16_t	cq_max_count;

	uint32_t	comp_eqn;

	uint32_t	mtt_base_addr_hi_sz;

	uint32_t	mtt_base_addr_lo;

	uint32_t	last_notified_idx;

	uint32_t	solicit_prod_idx;

	uint32_t	cons;

	uint32_t	prod;

	uint32_t	reserved2[2];

	uint32_t	db_rec_addr_hi;
	uint32_t	db_rec_addr_lo;

} __packed;

struct mlx_cq_entry {
	uint32_t	qpn_flags;

	uint32_t	what;

	uint32_t	srq_rqpn;

	uint16_t	smac_hi;
	uint16_t	vid_sl;

	uint32_t	smac_lo;

	uint32_t	byte_cnt;

	uint16_t	checksum;
	uint16_t	wqe_counter;

	uint8_t		reserved1[3];
	uint8_t		owner_sr_op;
} __packed;

#define MLX_SEND_WQE_SEGS	3
#define MLX_RECV_WQE_SEGS	2

#define MLX_WQE_OWNER	(1 << 31)

#define MLX_WQE_FENCE	(1 << 6)

#define MLX_WQE_FLAG_C	(1 << 2 | 1 << 3)

struct mlx_wqe_segment {
	uint32_t	size;
	uint32_t	lkey;
	uint32_t	local_addr_hi;
	uint32_t	local_addr_lo;
} __packed;

struct mlx_send_wqe {
	uint32_t	owner_opcode;

	uint32_t	ds_fence;

	uint32_t	flags_buf;

	uint32_t	immediate;

	struct mlx_wqe_segment segs[MLX_SEND_WQE_SEGS];
} __packed;

struct mlx_recv_wqe {
	struct mlx_wqe_segment segs[MLX_RECV_WQE_SEGS];
} __packed;

struct mlx_qp_addr_path {
	uint8_t		fl;
	uint8_t		vlan_control;
	uint8_t		disable_pkey_check;
	uint8_t		pkey_index;
	
	uint8_t		counter_index;
	uint8_t		grh_mylmc;
	uint16_t	rlid;

	uint8_t		ack_timeout;
	uint8_t		mgid_index;
	uint8_t		max_stat_rate;
	uint8_t		hop_limit;

	uint32_t	flow_label_tclass;

	uint32_t	rgid[4];

	uint8_t		sched_queue;
	uint8_t		vlan_index;
	uint8_t		feup;
	uint8_t		fvl_rx;

	uint16_t	vlan_counter;
	uint16_t	dmac_hi;

	uint32_t	dmac_lo;
} __packed;

#define MLX_QP_PM_ARMED		0
#define MLX_QP_PM_REARM		1
#define MLX_QP_PM_MIGRATED	3
#define MLX_QP_PM_SHIFT		11

#define MLX_QP_ST_ETH		(3 << 16)

#define MLX_QP_STATE_RST	0
#define MLX_QP_STATE_INIT	1
#define MLX_QP_STATE_RTR	2
#define MLX_QP_STATE_RTS	3
#define MLX_QP_STATE_SQER	4
#define MLX_QP_STATE_SQD	5
#define MLX_QP_STATE_ERR	6
#define MLX_QP_STATE_SQDR	7
#define MLX_QP_STATE_SHIFT	28

#define MLX_QP_SQ_STRIDE_SHIFT	8
#define MLX_QP_SQ_SIZE_SHIFT	11
#define MLX_QP_RQ_STRIDE_SHIFT	16
#define MLX_QP_RQ_SIZE_SHIFT	19

#define MLX_QP_MSG_MAX		31
#define MLX_QP_MSG_MAX_SHIFT	24

#define MLX_MTU_ETH		7
#define MLX_QP_MTU_SHIFT	29

struct mlx_qp_context {
	uint32_t	state;			// 0

	uint32_t	pd;			// 1

	uint32_t	wq_params;		// 2

	uint32_t	usr_page;		// 3

	uint32_t	local_qpn;		// 4

	uint32_t	remote_qpn;		// 5

	struct mlx_qp_addr_path primary;

	struct mlx_qp_addr_path alternative;

	uint8_t		cur_retry_cnt;
	uint8_t		rnr_retry;
	uint8_t		retry_count;
	uint8_t		ack_req_freq;

	uint32_t	qreserved1;

	uint32_t	next_send_psn;

	uint32_t	cqn_send;		// should be 31

	uint32_t	qreserved2[2];		// 32, 33

	uint32_t	last_acked_psn;		// 34

	uint32_t	ssn;			// 35

	uint16_t	page_offset_atomic;
	uint16_t	rra_max_pf;		// 36

	uint32_t	next_rcv_psn;		// 37

	uint32_t	srcd;			// 38

	uint32_t	cqn_recv;		// 39

	uint32_t	db_rec_addr_hi;		// 40
	uint32_t	db_rec_addr_lo;		// 41

	uint32_t	q_key;			// 42

	uint32_t	srqn;			// 43

	uint32_t	rmsn;			// 44

	uint16_t	sq_wqe_count;
	uint16_t	rq_wqe_count;		// 45

	uint32_t	qreserved3[2];		// 46 47

	uint32_t	rmc_parent_qpn;		// 48

	uint32_t	base_mkey;		// 49

	uint32_t	mtt_base_addr_hi_sz;	// 50
	uint32_t	mtt_base_addr_lo;	// 51

	uint16_t	vft_lan;
	uint16_t	cs_ctl;

	uint16_t	exch_base;
	uint16_t	exch_size;

	uint32_t	remote_id;

	uint16_t	fcp_mtu;
	uint16_t	id_indx_vft_hop_count;
} __packed;

struct mlx_qp_state {
	uint32_t	param_mask;

	uint32_t	reserved1;

	struct mlx_qp_context c;

	uint32_t	reserved2[36];
} __packed;

#define MLX_SET_PORT_GEN	0x0000
#define MLX_SET_PORT_RQP	0x0100
#define MLX_SET_PORT_MAC	0x0200
#define MLX_SET_PORT_VLAN	0x0300
#define MLX_SET_PORT_PRIO	0x0400

struct mlx_set_port_gen {
	uint32_t	flags;

	uint16_t	reserved1;
	uint16_t	mtu;

	uint8_t		pptx;
	uint8_t		pfctx;
	uint16_t	reserved2;

	uint8_t		pprx;
	uint8_t		pfcrx;
	uint16_t	reserved3;
} __packed;

struct mlx_set_port_rqp {
	uint32_t	base_qpn;

	uint8_t		reserved1;
	uint8_t		n_mac;
	uint8_t		n_vlan;
	uint8_t		n_prio;

	uint32_t	mac_miss_idx;

	uint8_t		intra_no_vlan;
	uint8_t		no_vlan_idx;
	uint8_t		intra_miss;
	uint8_t		vlan_miss_idx;

	uint32_t	no_vlan_prio;

	uint32_t	promisc_qpn;

	uint32_t	def_mcast_qpn;
} __packed;

struct mlx_query_port {
	uint8_t		link_up;
	uint8_t		autoneg;
	uint16_t	mtu;
	uint8_t		reserved;
	uint8_t		link_speed;
	uint16_t	reserved2[5];
	uint64_t	mac;
	uint8_t		xcvr;
} __packed;
