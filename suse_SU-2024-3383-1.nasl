#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3383-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207676);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id(
    "CVE-2023-52489",
    "CVE-2023-52581",
    "CVE-2023-52668",
    "CVE-2023-52688",
    "CVE-2023-52735",
    "CVE-2023-52859",
    "CVE-2023-52885",
    "CVE-2023-52886",
    "CVE-2023-52887",
    "CVE-2023-52889",
    "CVE-2024-26590",
    "CVE-2024-26631",
    "CVE-2024-26637",
    "CVE-2024-26668",
    "CVE-2024-26669",
    "CVE-2024-26677",
    "CVE-2024-26682",
    "CVE-2024-26683",
    "CVE-2024-26691",
    "CVE-2024-26735",
    "CVE-2024-26808",
    "CVE-2024-26809",
    "CVE-2024-26812",
    "CVE-2024-26835",
    "CVE-2024-26837",
    "CVE-2024-26849",
    "CVE-2024-26851",
    "CVE-2024-26889",
    "CVE-2024-26920",
    "CVE-2024-26944",
    "CVE-2024-26976",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27024",
    "CVE-2024-27049",
    "CVE-2024-27050",
    "CVE-2024-27079",
    "CVE-2024-27403",
    "CVE-2024-27433",
    "CVE-2024-27437",
    "CVE-2024-31076",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35897",
    "CVE-2024-35902",
    "CVE-2024-35913",
    "CVE-2024-35939",
    "CVE-2024-35949",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-36288",
    "CVE-2024-36489",
    "CVE-2024-36881",
    "CVE-2024-36907",
    "CVE-2024-36909",
    "CVE-2024-36910",
    "CVE-2024-36911",
    "CVE-2024-36929",
    "CVE-2024-36933",
    "CVE-2024-36939",
    "CVE-2024-36970",
    "CVE-2024-36979",
    "CVE-2024-38548",
    "CVE-2024-38563",
    "CVE-2024-38609",
    "CVE-2024-38662",
    "CVE-2024-39476",
    "CVE-2024-39483",
    "CVE-2024-39484",
    "CVE-2024-39486",
    "CVE-2024-39488",
    "CVE-2024-39489",
    "CVE-2024-39491",
    "CVE-2024-39493",
    "CVE-2024-39497",
    "CVE-2024-39499",
    "CVE-2024-39500",
    "CVE-2024-39501",
    "CVE-2024-39505",
    "CVE-2024-39506",
    "CVE-2024-39508",
    "CVE-2024-39509",
    "CVE-2024-39510",
    "CVE-2024-40899",
    "CVE-2024-40900",
    "CVE-2024-40902",
    "CVE-2024-40903",
    "CVE-2024-40904",
    "CVE-2024-40905",
    "CVE-2024-40909",
    "CVE-2024-40910",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40913",
    "CVE-2024-40916",
    "CVE-2024-40920",
    "CVE-2024-40921",
    "CVE-2024-40922",
    "CVE-2024-40924",
    "CVE-2024-40926",
    "CVE-2024-40927",
    "CVE-2024-40929",
    "CVE-2024-40930",
    "CVE-2024-40932",
    "CVE-2024-40934",
    "CVE-2024-40936",
    "CVE-2024-40938",
    "CVE-2024-40939",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40944",
    "CVE-2024-40945",
    "CVE-2024-40954",
    "CVE-2024-40956",
    "CVE-2024-40957",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40962",
    "CVE-2024-40964",
    "CVE-2024-40967",
    "CVE-2024-40976",
    "CVE-2024-40977",
    "CVE-2024-40978",
    "CVE-2024-40981",
    "CVE-2024-40982",
    "CVE-2024-40984",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40989",
    "CVE-2024-40990",
    "CVE-2024-40992",
    "CVE-2024-40994",
    "CVE-2024-40995",
    "CVE-2024-40997",
    "CVE-2024-41000",
    "CVE-2024-41001",
    "CVE-2024-41002",
    "CVE-2024-41004",
    "CVE-2024-41007",
    "CVE-2024-41009",
    "CVE-2024-41010",
    "CVE-2024-41011",
    "CVE-2024-41012",
    "CVE-2024-41015",
    "CVE-2024-41016",
    "CVE-2024-41020",
    "CVE-2024-41022",
    "CVE-2024-41024",
    "CVE-2024-41025",
    "CVE-2024-41028",
    "CVE-2024-41032",
    "CVE-2024-41035",
    "CVE-2024-41036",
    "CVE-2024-41037",
    "CVE-2024-41038",
    "CVE-2024-41039",
    "CVE-2024-41040",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41045",
    "CVE-2024-41048",
    "CVE-2024-41049",
    "CVE-2024-41050",
    "CVE-2024-41051",
    "CVE-2024-41056",
    "CVE-2024-41057",
    "CVE-2024-41058",
    "CVE-2024-41059",
    "CVE-2024-41060",
    "CVE-2024-41061",
    "CVE-2024-41062",
    "CVE-2024-41063",
    "CVE-2024-41064",
    "CVE-2024-41065",
    "CVE-2024-41066",
    "CVE-2024-41068",
    "CVE-2024-41069",
    "CVE-2024-41070",
    "CVE-2024-41071",
    "CVE-2024-41072",
    "CVE-2024-41073",
    "CVE-2024-41074",
    "CVE-2024-41075",
    "CVE-2024-41076",
    "CVE-2024-41078",
    "CVE-2024-41079",
    "CVE-2024-41080",
    "CVE-2024-41081",
    "CVE-2024-41084",
    "CVE-2024-41087",
    "CVE-2024-41088",
    "CVE-2024-41089",
    "CVE-2024-41092",
    "CVE-2024-41093",
    "CVE-2024-41094",
    "CVE-2024-41095",
    "CVE-2024-41096",
    "CVE-2024-41097",
    "CVE-2024-41098",
    "CVE-2024-42064",
    "CVE-2024-42069",
    "CVE-2024-42070",
    "CVE-2024-42073",
    "CVE-2024-42074",
    "CVE-2024-42076",
    "CVE-2024-42077",
    "CVE-2024-42079",
    "CVE-2024-42080",
    "CVE-2024-42082",
    "CVE-2024-42085",
    "CVE-2024-42086",
    "CVE-2024-42087",
    "CVE-2024-42089",
    "CVE-2024-42090",
    "CVE-2024-42092",
    "CVE-2024-42093",
    "CVE-2024-42095",
    "CVE-2024-42096",
    "CVE-2024-42097",
    "CVE-2024-42098",
    "CVE-2024-42101",
    "CVE-2024-42104",
    "CVE-2024-42105",
    "CVE-2024-42106",
    "CVE-2024-42107",
    "CVE-2024-42109",
    "CVE-2024-42110",
    "CVE-2024-42113",
    "CVE-2024-42114",
    "CVE-2024-42115",
    "CVE-2024-42117",
    "CVE-2024-42119",
    "CVE-2024-42120",
    "CVE-2024-42121",
    "CVE-2024-42122",
    "CVE-2024-42124",
    "CVE-2024-42125",
    "CVE-2024-42126",
    "CVE-2024-42127",
    "CVE-2024-42130",
    "CVE-2024-42131",
    "CVE-2024-42132",
    "CVE-2024-42133",
    "CVE-2024-42136",
    "CVE-2024-42137",
    "CVE-2024-42138",
    "CVE-2024-42139",
    "CVE-2024-42141",
    "CVE-2024-42142",
    "CVE-2024-42143",
    "CVE-2024-42144",
    "CVE-2024-42145",
    "CVE-2024-42147",
    "CVE-2024-42148",
    "CVE-2024-42152",
    "CVE-2024-42153",
    "CVE-2024-42155",
    "CVE-2024-42156",
    "CVE-2024-42157",
    "CVE-2024-42158",
    "CVE-2024-42159",
    "CVE-2024-42161",
    "CVE-2024-42162",
    "CVE-2024-42223",
    "CVE-2024-42224",
    "CVE-2024-42225",
    "CVE-2024-42226",
    "CVE-2024-42227",
    "CVE-2024-42228",
    "CVE-2024-42229",
    "CVE-2024-42230",
    "CVE-2024-42232",
    "CVE-2024-42236",
    "CVE-2024-42237",
    "CVE-2024-42238",
    "CVE-2024-42239",
    "CVE-2024-42240",
    "CVE-2024-42241",
    "CVE-2024-42244",
    "CVE-2024-42245",
    "CVE-2024-42246",
    "CVE-2024-42247",
    "CVE-2024-42250",
    "CVE-2024-42253",
    "CVE-2024-42259",
    "CVE-2024-42268",
    "CVE-2024-42269",
    "CVE-2024-42270",
    "CVE-2024-42271",
    "CVE-2024-42274",
    "CVE-2024-42276",
    "CVE-2024-42277",
    "CVE-2024-42278",
    "CVE-2024-42279",
    "CVE-2024-42280",
    "CVE-2024-42281",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42287",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42290",
    "CVE-2024-42291",
    "CVE-2024-42292",
    "CVE-2024-42295",
    "CVE-2024-42298",
    "CVE-2024-42301",
    "CVE-2024-42302",
    "CVE-2024-42303",
    "CVE-2024-42308",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42311",
    "CVE-2024-42312",
    "CVE-2024-42313",
    "CVE-2024-42314",
    "CVE-2024-42315",
    "CVE-2024-42316",
    "CVE-2024-42318",
    "CVE-2024-42319",
    "CVE-2024-42320",
    "CVE-2024-42322",
    "CVE-2024-43816",
    "CVE-2024-43817",
    "CVE-2024-43818",
    "CVE-2024-43819",
    "CVE-2024-43821",
    "CVE-2024-43823",
    "CVE-2024-43824",
    "CVE-2024-43825",
    "CVE-2024-43826",
    "CVE-2024-43829",
    "CVE-2024-43830",
    "CVE-2024-43831",
    "CVE-2024-43833",
    "CVE-2024-43834",
    "CVE-2024-43837",
    "CVE-2024-43839",
    "CVE-2024-43840",
    "CVE-2024-43841",
    "CVE-2024-43842",
    "CVE-2024-43846",
    "CVE-2024-43847",
    "CVE-2024-43849",
    "CVE-2024-43850",
    "CVE-2024-43851",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43855",
    "CVE-2024-43856",
    "CVE-2024-43858",
    "CVE-2024-43860",
    "CVE-2024-43861",
    "CVE-2024-43863",
    "CVE-2024-43864",
    "CVE-2024-43866",
    "CVE-2024-43867",
    "CVE-2024-43871",
    "CVE-2024-43872",
    "CVE-2024-43873",
    "CVE-2024-43874",
    "CVE-2024-43875",
    "CVE-2024-43876",
    "CVE-2024-43877",
    "CVE-2024-43879",
    "CVE-2024-43880",
    "CVE-2024-43881",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-43884",
    "CVE-2024-43885",
    "CVE-2024-43889",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43895",
    "CVE-2024-43897",
    "CVE-2024-43899",
    "CVE-2024-43900",
    "CVE-2024-43902",
    "CVE-2024-43903",
    "CVE-2024-43905",
    "CVE-2024-43906",
    "CVE-2024-43907",
    "CVE-2024-43908",
    "CVE-2024-43909",
    "CVE-2024-43911",
    "CVE-2024-43912",
    "CVE-2024-44931",
    "CVE-2024-44938",
    "CVE-2024-44939"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3383-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:3383-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:3383-1 advisory.

    The SUSE Linux Enterprise 15 SP6 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-43911: wifi: mac80211: fix NULL dereference at band check in starting tx ba session
    (bsc#1229827).
    - CVE-2024-43899: drm/amd/display: Fix null pointer deref in dcn20_resource.c (bsc#1229754).
    - CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
    - CVE-2024-43880: kabi: lib: objagg: Put back removed metod in struct objagg_ops (bsc#1229481).
    - CVE-2024-43866: net/mlx5: Always drain health in shutdown callback (bsc#1229495).
    - CVE-2024-43864: net/mlx5e: Fix CT entry update leaks of modify header context (bsc#1229496).
    - CVE-2024-43855: md: fix deadlock between mddev_suspend and flush bio (bsc#1229342).
    - CVE-2024-43854: block: initialize integrity buffer to zero before writing it to media (bsc#1229345)
    - CVE-2024-43850: soc: qcom: icc-bwmon: Fix refcount imbalance seen during bwmon_remove (bsc#1229316).
    - CVE-2024-43839: bna: adjust 'name' buf size of bna_tcb and bna_ccb structures (bsc#1229301).
    - CVE-2024-43837: bpf: Fix updating attached freplace prog in prog_array map (bsc#1229297).
    - CVE-2024-43834: xdp: fix invalid wait context of page_pool_destroy() (bsc#1229314)
    - CVE-2024-43831: media: mediatek: vcodec: Handle invalid decoder vsi (bsc#1229309).
    - CVE-2024-43821: scsi: lpfc: Fix a possible null pointer dereference (bsc#1229315).
    - CVE-2024-42322: ipvs: properly dereference pe in ip_vs_add_service (bsc#1229347)
    - CVE-2024-42318: landlock: Do not lose track of restrictions on cred_transfer (bsc#1229351).
    - CVE-2024-42316: mm/mglru: fix div-by-zero in vmpressure_calc_level() (bsc#1229353).
    - CVE-2024-42312: sysctl: always initialize i_uid/i_gid (bsc#1229357)
    - CVE-2024-42308: Update DRM patch reference (bsc#1229411)
    - CVE-2024-42301: dev/parport: fix the array out-of-bounds risk (bsc#1229407).
    - CVE-2024-42295: nilfs2: handle inconsistent state in nilfs_btnode_create_block() (bsc#1229370).
    - CVE-2024-42291: ice: Add a per-VF limit on number of FDIR filters (bsc#1229374).
    - CVE-2024-42290: irqchip/imx-irqsteer: Handle runtime power management correctly (bsc#1229379).
    - CVE-2024-42284: tipc: Return non-zero value from tipc_udp_addr2str() on error (bsc#1229382)
    - CVE-2024-42283: net: nexthop: Initialize all fields in dumped nexthops (bsc#1229383)
    - CVE-2024-42281: bpf: Fix a segment issue when downgrading gso_size (bsc#1229386).
    - CVE-2024-42277: iommu: sprd: Avoid NULL deref in sprd_iommu_hw_en (bsc#1229409).
    - CVE-2024-42270: netfilter: iptables: Fix null-ptr-deref in iptable_nat_table_init() (bsc#1229404).
    - CVE-2024-42269: netfilter: iptables: Fix potential null-ptr-deref in ip6table_nat_table_init()
    (bsc#1229402).
    - CVE-2024-42268: net/mlx5: Fix missing lock on sync reset reload (bsc#1229391).
    - CVE-2024-42247: wireguard: allowedips: avoid unaligned 64-bit memory accesses (bsc#1228988).
    - CVE-2024-42246: net, sunrpc: Remap EPERM in case of connection failure in xs_tcp_setup_socket
    (bsc#1228989).
    - CVE-2024-42245: Revert 'sched/fair: Make sure to try to detach at least one movable task' (bsc#1228978).
    - CVE-2024-42241: mm/shmem: disable PMD-sized page cache if needed (bsc#1228986).
    - CVE-2024-42224: net: dsa: mv88e6xxx: Correct check for empty list (bsc#1228723).
    - CVE-2024-42162: gve: Account for stopped queues when reading NIC stats (bsc#1228706).
    - CVE-2024-42161: bpf: avoid uninitialized value in BPF_CORE_READ_BITFIELD (bsc#1228756).
    - CVE-2024-42159: scsi: mpi3mr: fix sanitise num_phys (bsc#1228754).
    - CVE-2024-42158: s390/pkey: Use kfree_sensitive() to fix Coccinelle warnings (bsc#1228720).
    - CVE-2024-42157: s390/pkey: Wipe sensitive data on failure (bsc#1228727).
    - CVE-2024-42156: s390/pkey: Wipe copies of clear-key structures on failure (bsc#1228722).
    - CVE-2024-42155: s390/pkey: Wipe copies of protected- and secure-keys (bsc#1228733).
    - CVE-2024-42148: bnx2x: Fix multiple UBSAN array-index-out-of-bounds (bsc#1228487).
    - CVE-2024-42145: IB/core: Implement a limit on UMAD receive List (bsc#1228743).
    - CVE-2024-42142: net/mlx5: E-switch, Create ingress ACL when needed (bsc#1228491).
    - CVE-2024-42139: ice: Fix improper extts handling (bsc#1228503).
    - CVE-2024-42138: mlxsw: core_linecards: Fix double memory deallocation in case of invalid INI file
    (bsc#1228500).
    - CVE-2024-42124: scsi: qedf: Make qedf_execute_tmf() non-preemptible (bsc#1228705).
    - CVE-2024-42122: drm/amd/display: Add NULL pointer check for kzalloc (bsc#1228591).
    - CVE-2024-42113: net: txgbe: initialize num_q_vectors for MSI/INTx interrupts (bsc#1228568).
    - CVE-2024-42110: net: ntb_netdev: Move ntb_netdev_rx_handler() to call netif_rx() from __netif_rx()
    (bsc#1228501).
    - CVE-2024-42109: netfilter: nf_tables: unconditionally flush pending work before notifier (bsc#1228505).
    - CVE-2024-42107: ice: Do not process extts if PTP is disabled (bsc#1228494).
    - CVE-2024-42106: inet_diag: Initialize pad field in struct inet_diag_req_v2 (bsc#1228493).
    - CVE-2024-42096: x86: stop playing stack games in profile_pc() (bsc#1228633).
    - CVE-2024-42095: serial: 8250_omap: Fix Errata i2310 with RX FIFO level check (bsc#1228446).
    - CVE-2024-42093: net/dpaa2: Avoid explicit cpumask var allocation on stack (bsc#1228680).
    - CVE-2024-42082: xdp: Remove WARN() from __xdp_reg_mem_model() (bsc#1228482).
    - CVE-2024-42079: gfs2: Fix NULL pointer dereference in gfs2_log_flush (bsc#1228672).
    - CVE-2024-42073: mlxsw: spectrum_buffers: Fix memory corruptions on Spectrum-4 systems (bsc#1228457).
    - CVE-2024-42070: netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers
    (bsc#1228470).
    - CVE-2024-41084: cxl/region: Avoid null pointer dereference in region lookup (bsc#1228472).
    - CVE-2024-41081: ila: block BH in ila_output() (bsc#1228617).
    - CVE-2024-41080: io_uring: fix possible deadlock in io_register_iowq_max_workers() (bsc#1228616).
    - CVE-2024-41078: btrfs: qgroup: fix quota root leak after quota disable failure (bsc#1228655).
    - CVE-2024-41076: NFSv4: Fix memory leak in nfs4_set_security_label (bsc#1228649).
    - CVE-2024-41075: cachefiles: add consistency check for copen/cread (bsc#1228646).
    - CVE-2024-41074: cachefiles: Set object to close if ondemand_id < 0 in copen (bsc#1228643).
    - CVE-2024-41070: KVM: PPC: Book3S HV: Prevent UAF in kvm_spapr_tce_attach_iommu_group() (bsc#1228581).
    - CVE-2024-41069: ASoC: topology: Fix route memory corruption (bsc#1228644).
    - CVE-2024-41068: s390/sclp: Fix sclp_init() cleanup on failure (bsc#1228579).
    - CVE-2024-41066: ibmvnic: add tx check to prevent skb leak (bsc#1228640).
    - CVE-2024-41064: powerpc/eeh: avoid possible crash when edev->pdev changes (bsc#1228599).
    - CVE-2024-41062: bluetooth/l2cap: sync sock recv cb and release (bsc#1228576).
    - CVE-2024-41058: cachefiles: fix slab-use-after-free in fscache_withdraw_volume() (bsc#1228459).
    - CVE-2024-41057: cachefiles: fix slab-use-after-free in cachefiles_withdraw_cookie() (bsc#1228462).
    - CVE-2024-41051: cachefiles: wait for ondemand_object_worker to finish when dropping object
    (bsc#1228468).
    - CVE-2024-41050: cachefiles: cyclic allocation of msg_id to avoid reuse (bsc#1228499).
    - CVE-2024-41048: skmsg: Skip zero length skb in sk_msg_recvmsg (bsc#1228565).
    - CVE-2024-41044: ppp: reject claimed-as-LCP but actually malformed packets (bsc#1228530).
    - CVE-2024-41041: udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port() (bsc#1228520).
    - CVE-2024-41040: net/sched: Fix UAF when resolving a clash (bsc#1228518).
    - CVE-2024-41036: net: ks8851: Fix deadlock with the SPI chip variant (bsc#1228496).
    - CVE-2024-41032: mm: vmalloc: check if a hash-index is in cpu_possible_mask (bsc#1228460).
    - CVE-2024-41020: filelock: Fix fcntl/close race recovery compat path (bsc#1228427).
    - CVE-2024-41015: ocfs2: add bounds checking to ocfs2_check_dir_entry() (bsc#1228409).
    - CVE-2024-41012: filelock: Remove locks reliably when fcntl/close race is detected (bsc#1228247).
    - CVE-2024-41010: bpf: Fix too early release of tcx_entry (bsc#1228021).
    - CVE-2024-41009: bpf: Fix overrunning reservations in ringbuf (bsc#1228020).
    - CVE-2024-41007: tcp: use signed arithmetic in tcp_rtx_probe0_timed_out() (bsc#1227863).
    - CVE-2024-41000: block/ioctl: prefer different overflow check (bsc#1227867).
    - CVE-2024-40995: net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc() (bsc#1227830).
    - CVE-2024-40994: ptp: fix integer overflow in max_vclocks_store (bsc#1227829).
    - CVE-2024-40989: KVM: arm64: Disassociate vcpus from redistributor region on teardown (bsc#1227823).
    - CVE-2024-40978: scsi: qedi: Fix crash while reading debugfs attribute (bsc#1227929).
    - CVE-2024-40959: xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr() (bsc#1227884).
    - CVE-2024-40958: netns: Make get_net_ns() handle zero refcount net (bsc#1227812).
    - CVE-2024-40957: seg6: fix parameter passing when calling NF_HOOK() in End.DX4 and End.DX6 behaviors
    (bsc#1227811).
    - CVE-2024-40956: dmaengine: idxd: Fix possible Use-After-Free in irq_process_work_list (bsc#1227810).
    - CVE-2024-40954: net: do not leave a dangling sk pointer, when socket creation fails (bsc#1227808)
    - CVE-2024-40939: net: wwan: iosm: Fix tainted pointer delete is case of region creation fail
    (bsc#1227799).
    - CVE-2024-40938: landlock: fix d_parent walk (bsc#1227840).
    - CVE-2024-40921: net: bridge: mst: pass vlan group directly to br_mst_vlan_set_state (bsc#1227784).
    - CVE-2024-40920: net: bridge: mst: fix suspicious rcu usage in br_mst_set_state (bsc#1227781).
    - CVE-2024-40909: bpf: Fix a potential use-after-free in bpf_link_free() (bsc#1227798).
    - CVE-2024-40905: ipv6: fix possible race in __fib6_drop_pcpu_from() (bsc#1227761)
    - CVE-2024-39506: liquidio: adjust a NULL pointer handling path in lio_vf_rep_copy_packet (bsc#1227729).
    - CVE-2024-39489: ipv6: sr: fix memleak in seg6_hmac_init_algo (bsc#1227623)
    - CVE-2024-38662: selftests/bpf: Cover verifier checks for mutating sockmap/sockhash (bsc#1226885).
    - CVE-2024-36979: net: bridge: mst: fix vlan use-after-free (bsc#1226604).
    - CVE-2024-36933: net: nsh: Use correct mac_offset to unwind gso skb in nsh_gso_segment() (bsc#1225832).
    - CVE-2024-36929: net: core: reject skb_copy(_expand) for fraglist GSO skbs (bsc#1225814).
    - CVE-2024-36911: hv_netvsc: Do not free decrypted memory (bsc#1225745).
    - CVE-2024-36910: uio_hv_generic: Do not free decrypted memory (bsc#1225717).
    - CVE-2024-36909: Drivers: hv: vmbus: Do not free ring buffers that couldn't be re-encrypted
    (bsc#1225744).
    - CVE-2024-36881: mm/userfaultfd: Fix reset ptes when close() for wr-protected (bsc#1225718).
    - CVE-2024-36489: tls: fix missing memory barrier in tls_init (bsc#1226874)
    - CVE-2024-36286: netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu()
    (bsc#1226801)
    - CVE-2024-36270: Fix reference in patches.suse/netfilter-tproxy-bail-out-if-IP-has-been-disabled-on.patch
    (bsc#1226798)
    - CVE-2024-35949: btrfs: make sure that WRITTEN is set on all metadata blocks (bsc#1224700).
    - CVE-2024-35939: Fixed leak pages on dma_set_decrypted() failure (bsc#1224535).
    - CVE-2024-35897: netfilter: nf_tables: discard table flag update with pending basechain deletion
    (bsc#1224510).
    - CVE-2024-27437: vfio/pci: Disable auto-enable of exclusive INTx IRQ (bsc#1222625).
    - CVE-2024-27433: clk: mediatek: mt7622-apmixedsys: Fix an error handling path in
    clk_mt8135_apmixed_probe() (bsc#1224711).
    - CVE-2024-27403: kabi: restore const specifier in flow_offload_route_init() (bsc#1224415).
    - CVE-2024-27079: iommu/vt-d: Fix NULL domain on device release (bsc#1223742).
    - CVE-2024-27024: net/rds: fix WARNING in rds_conn_connect_if_down (bsc#1223777).
    - CVE-2024-27011: netfilter: nf_tables: fix memleak in map from abort path (bsc#1223803).
    - CVE-2024-27010: net/sched: Fix mirred deadlock on device recursion (bsc#1223720).
    - CVE-2024-26851: netfilter: nf_conntrack_h323: Add protection for bmp length out of range (bsc#1223074)
    - CVE-2024-26837: net: bridge: switchdev: race between creation of new group memberships and generation of
    the list of MDB events to replay (bsc#1222973).
    - CVE-2024-26835: netfilter: nf_tables: set dormant flag on hook register failure (bsc#1222967).
    - CVE-2024-26812: kABI: vfio: struct virqfd kABI workaround (bsc#1222808).
    - CVE-2024-26809: netfilter: nft_set_pipapo: release elements in clone only from destroy path
    (bsc#1222633).
    - CVE-2024-26808: netfilter: nft_chain_filter: handle NETDEV_UNREGISTER for inet/ingress basechain
    (bsc#1222634).
    - CVE-2024-26735: ipv6: sr: fix possible use-after-free and null-ptr-deref (bsc#1222372).
    - CVE-2024-26677: blacklist.conf: Add e7870cf13d20 ('rxrpc: Fix delayed ACKs to not set the reference
    serial number') (bsc#1222387)
    - CVE-2024-26669: kABI fix for net/sched: flower: Fix chain template offload (bsc#1222350).
    - CVE-2024-26668: netfilter: nft_limit: reject configurations that cause integer overflow (bsc#1222335).
    - CVE-2024-26631: ipv6: mcast: fix data-race in ipv6_mc_down / mld_ifc_work (bsc#1221630).
    - CVE-2024-26590: erofs: fix inconsistent per-file compression format (bsc#1220252).
    - CVE-2023-52889: apparmor: Fix null pointer deref when receiving skb during sock creation (bsc#1229287).
    - CVE-2023-52859: perf: hisi: Fix use-after-free when register pmu fails (bsc#1225582).
    - CVE-2023-52581: netfilter: nf_tables: fix memleak when more than 255 elements expired (bsc#1220877).
    - CVE-2023-52489: mm/sparsemem: fix race in accessing memory_section->usage (bsc#1221326).



Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1012628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230413");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-September/019497.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6a2ae32");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27050");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27403");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27433");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39491");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39499");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41040");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41050");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41092");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41094");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42092");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42109");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42121");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42122");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42132");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42136");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42137");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42152");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42223");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42225");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42227");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42238");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42245");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42246");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42253");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42274");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42277");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42278");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42298");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42303");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42308");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42316");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43824");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44939");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-6_4_0-150600_23_22-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-64kb-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'cluster-md-kmp-64kb-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-default-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-64kb-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-default-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-allwinner-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-altera-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amazon-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amd-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amlogic-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-apm-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-apple-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-arm-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-broadcom-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-cavium-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-exynos-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-freescale-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-hisilicon-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-lg-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-marvell-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-mediatek-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-nvidia-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-qcom-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-renesas-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-rockchip-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-socionext-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-sprd-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-xilinx-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-64kb-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-default-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-extra-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-livepatch-devel-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-optional-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-devel-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-livepatch-devel-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-vdso-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.22.1.150600.12.8.3', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-rebuild-6.4.0-150600.23.22.1.150600.12.8.3', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-rebuild-6.4.0-150600.23.22.1.150600.12.8.3', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-livepatch-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-livepatch-devel-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-optional-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-vdso-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-devel-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-devel-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-livepatch-devel-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-livepatch-devel-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-vdso-6.4.0-150600.23.22.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-obs-qa-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-vanilla-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.22.1', 'cpu':'s390x', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-64kb-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-default-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-64kb-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-default-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-64kb-6.4.0-150600.23.22.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.22.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'dlm-kmp-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'gfs2-kmp-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'ocfs2-kmp-default-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'kernel-default-livepatch-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-default-livepatch-devel-6.4.0-150600.23.22.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-livepatch-6_4_0-150600_23_22-default-1-150600.13.3.3', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.22.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-64kb / cluster-md-kmp-default / dlm-kmp-64kb / etc');
}
