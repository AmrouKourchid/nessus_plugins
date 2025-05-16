#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2947-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205747);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/26");

  script_cve_id(
    "CVE-2021-47086",
    "CVE-2021-47103",
    "CVE-2021-47186",
    "CVE-2021-47402",
    "CVE-2021-47546",
    "CVE-2021-47547",
    "CVE-2021-47588",
    "CVE-2021-47590",
    "CVE-2021-47591",
    "CVE-2021-47593",
    "CVE-2021-47598",
    "CVE-2021-47599",
    "CVE-2021-47606",
    "CVE-2021-47622",
    "CVE-2021-47623",
    "CVE-2021-47624",
    "CVE-2022-48713",
    "CVE-2022-48730",
    "CVE-2022-48732",
    "CVE-2022-48749",
    "CVE-2022-48756",
    "CVE-2022-48773",
    "CVE-2022-48774",
    "CVE-2022-48775",
    "CVE-2022-48776",
    "CVE-2022-48777",
    "CVE-2022-48778",
    "CVE-2022-48780",
    "CVE-2022-48783",
    "CVE-2022-48784",
    "CVE-2022-48785",
    "CVE-2022-48786",
    "CVE-2022-48787",
    "CVE-2022-48788",
    "CVE-2022-48789",
    "CVE-2022-48790",
    "CVE-2022-48791",
    "CVE-2022-48792",
    "CVE-2022-48793",
    "CVE-2022-48794",
    "CVE-2022-48796",
    "CVE-2022-48797",
    "CVE-2022-48798",
    "CVE-2022-48799",
    "CVE-2022-48800",
    "CVE-2022-48801",
    "CVE-2022-48802",
    "CVE-2022-48803",
    "CVE-2022-48804",
    "CVE-2022-48805",
    "CVE-2022-48806",
    "CVE-2022-48807",
    "CVE-2022-48809",
    "CVE-2022-48810",
    "CVE-2022-48811",
    "CVE-2022-48812",
    "CVE-2022-48813",
    "CVE-2022-48814",
    "CVE-2022-48815",
    "CVE-2022-48816",
    "CVE-2022-48817",
    "CVE-2022-48818",
    "CVE-2022-48820",
    "CVE-2022-48821",
    "CVE-2022-48822",
    "CVE-2022-48823",
    "CVE-2022-48824",
    "CVE-2022-48825",
    "CVE-2022-48826",
    "CVE-2022-48827",
    "CVE-2022-48828",
    "CVE-2022-48829",
    "CVE-2022-48830",
    "CVE-2022-48831",
    "CVE-2022-48834",
    "CVE-2022-48835",
    "CVE-2022-48836",
    "CVE-2022-48837",
    "CVE-2022-48838",
    "CVE-2022-48839",
    "CVE-2022-48840",
    "CVE-2022-48841",
    "CVE-2022-48842",
    "CVE-2022-48843",
    "CVE-2022-48844",
    "CVE-2022-48846",
    "CVE-2022-48847",
    "CVE-2022-48849",
    "CVE-2022-48850",
    "CVE-2022-48851",
    "CVE-2022-48852",
    "CVE-2022-48853",
    "CVE-2022-48855",
    "CVE-2022-48856",
    "CVE-2022-48857",
    "CVE-2022-48858",
    "CVE-2022-48859",
    "CVE-2022-48860",
    "CVE-2022-48861",
    "CVE-2022-48862",
    "CVE-2022-48863",
    "CVE-2022-48864",
    "CVE-2022-48866",
    "CVE-2023-1582",
    "CVE-2023-37453",
    "CVE-2023-52435",
    "CVE-2023-52573",
    "CVE-2023-52580",
    "CVE-2023-52591",
    "CVE-2023-52735",
    "CVE-2023-52751",
    "CVE-2023-52762",
    "CVE-2023-52775",
    "CVE-2023-52812",
    "CVE-2023-52857",
    "CVE-2023-52863",
    "CVE-2023-52885",
    "CVE-2023-52886",
    "CVE-2024-25741",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26615",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26641",
    "CVE-2024-26661",
    "CVE-2024-26663",
    "CVE-2024-26665",
    "CVE-2024-26800",
    "CVE-2024-26802",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26863",
    "CVE-2024-26889",
    "CVE-2024-26920",
    "CVE-2024-26935",
    "CVE-2024-26961",
    "CVE-2024-26976",
    "CVE-2024-27015",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27025",
    "CVE-2024-27065",
    "CVE-2024-27402",
    "CVE-2024-27437",
    "CVE-2024-35805",
    "CVE-2024-35819",
    "CVE-2024-35837",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35889",
    "CVE-2024-35890",
    "CVE-2024-35893",
    "CVE-2024-35899",
    "CVE-2024-35934",
    "CVE-2024-35949",
    "CVE-2024-35961",
    "CVE-2024-35979",
    "CVE-2024-35995",
    "CVE-2024-36000",
    "CVE-2024-36004",
    "CVE-2024-36288",
    "CVE-2024-36889",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36909",
    "CVE-2024-36910",
    "CVE-2024-36911",
    "CVE-2024-36912",
    "CVE-2024-36913",
    "CVE-2024-36914",
    "CVE-2024-36919",
    "CVE-2024-36923",
    "CVE-2024-36924",
    "CVE-2024-36926",
    "CVE-2024-36939",
    "CVE-2024-36941",
    "CVE-2024-36942",
    "CVE-2024-36944",
    "CVE-2024-36946",
    "CVE-2024-36947",
    "CVE-2024-36950",
    "CVE-2024-36952",
    "CVE-2024-36955",
    "CVE-2024-36959",
    "CVE-2024-36974",
    "CVE-2024-38548",
    "CVE-2024-38555",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38570",
    "CVE-2024-38586",
    "CVE-2024-38588",
    "CVE-2024-38598",
    "CVE-2024-38628",
    "CVE-2024-39276",
    "CVE-2024-39371",
    "CVE-2024-39463",
    "CVE-2024-39472",
    "CVE-2024-39475",
    "CVE-2024-39482",
    "CVE-2024-39487",
    "CVE-2024-39488",
    "CVE-2024-39490",
    "CVE-2024-39493",
    "CVE-2024-39494",
    "CVE-2024-39497",
    "CVE-2024-39499",
    "CVE-2024-39500",
    "CVE-2024-39501",
    "CVE-2024-39502",
    "CVE-2024-39505",
    "CVE-2024-39506",
    "CVE-2024-39507",
    "CVE-2024-39508",
    "CVE-2024-39509",
    "CVE-2024-40900",
    "CVE-2024-40901",
    "CVE-2024-40902",
    "CVE-2024-40903",
    "CVE-2024-40904",
    "CVE-2024-40906",
    "CVE-2024-40908",
    "CVE-2024-40909",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40916",
    "CVE-2024-40919",
    "CVE-2024-40923",
    "CVE-2024-40924",
    "CVE-2024-40927",
    "CVE-2024-40929",
    "CVE-2024-40931",
    "CVE-2024-40932",
    "CVE-2024-40934",
    "CVE-2024-40935",
    "CVE-2024-40937",
    "CVE-2024-40940",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40945",
    "CVE-2024-40953",
    "CVE-2024-40954",
    "CVE-2024-40956",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40966",
    "CVE-2024-40967",
    "CVE-2024-40970",
    "CVE-2024-40972",
    "CVE-2024-40976",
    "CVE-2024-40977",
    "CVE-2024-40981",
    "CVE-2024-40982",
    "CVE-2024-40984",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40989",
    "CVE-2024-40990",
    "CVE-2024-40994",
    "CVE-2024-40998",
    "CVE-2024-40999",
    "CVE-2024-41002",
    "CVE-2024-41004",
    "CVE-2024-41006",
    "CVE-2024-41009",
    "CVE-2024-41011",
    "CVE-2024-41012",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-41015",
    "CVE-2024-41016",
    "CVE-2024-41017",
    "CVE-2024-41040",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41048",
    "CVE-2024-41057",
    "CVE-2024-41058",
    "CVE-2024-41059",
    "CVE-2024-41063",
    "CVE-2024-41064",
    "CVE-2024-41066",
    "CVE-2024-41069",
    "CVE-2024-41070",
    "CVE-2024-41071",
    "CVE-2024-41072",
    "CVE-2024-41076",
    "CVE-2024-41078",
    "CVE-2024-41081",
    "CVE-2024-41087",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-42070",
    "CVE-2024-42079",
    "CVE-2024-42093",
    "CVE-2024-42096",
    "CVE-2024-42105",
    "CVE-2024-42122",
    "CVE-2024-42124",
    "CVE-2024-42145",
    "CVE-2024-42161",
    "CVE-2024-42224",
    "CVE-2024-42230"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2947-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:2947-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:2947-1 advisory.

    The SUSE Linux Enterprise 15 SP5 Azure kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2021-47086: phonet/pep: refuse to enable an unbound pipe (bsc#1220952).
    - CVE-2021-47103: net: sock: preserve kabi for sock (bsc#1221010).
    - CVE-2021-47186: ipc: check for null after calling kmemdup (bsc#1222702).
    - CVE-2021-47546: Kabi fix for ipv6: fix memory leak in fib6_rule_suppress (bsc#1225504).
    - CVE-2021-47547: net: tulip: de4x5: fix the problem that the array 'lp->phy' may be out of bound
    (bsc#1225505).
    - CVE-2021-47588: sit: do not call ipip6_dev_free() from sit_init_net() (bsc#1226568).
    - CVE-2021-47590: mptcp: fix deadlock in __mptcp_push_pending() (bsc#1226565).
    - CVE-2021-47591: mptcp: remove tcp ulp setsockopt support (bsc#1226570).
    - CVE-2021-47593: mptcp: clear 'kern' flag from fallback sockets (bsc#1226551).
    - CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init() (bsc#1226574).
    - CVE-2021-47599: btrfs: use latest_dev in btrfs_show_devname (bsc#1226571)
    - CVE-2021-47606: net: netlink: af_netlink: Prevent empty skb by adding a check on len (bsc#1226555).
    - CVE-2021-47623: powerpc/fixmap: Fix VM debug warning on unmap (bsc#1227919).
    - CVE-2022-48785: ipv6: mcast: use rcu-safe version of ipv6_get_lladdr() (bsc#1227927)
    - CVE-2022-48810: ipmr,ip6mr: acquire RTNL before calling ip[6]mr_free_table() on failure path
    (bsc#1227936).
    - CVE-2022-48850: net-sysfs: add check for netdevice being present to speed_show (bsc#1228071)
    - CVE-2022-48855: sctp: fix kernel-infoleak for SCTP sockets (bsc#1228003).
    - CVE-2023-52435: net: prevent mss overflow in skb_segment() (bsc#1220138).
    - CVE-2023-52573: net: rds: Fix possible NULL-pointer dereference (bsc#1220869)
    - CVE-2023-52580: net/core: Fix ETH_P_1588 flow dissector (bsc#1220876).
    - CVE-2023-52751: smb: client: fix use-after-free in smb2_query_info_compound() (bsc#1225489).
    - CVE-2023-52775: net/smc: avoid data corruption caused by decline (bsc#1225088).
    - CVE-2023-52812: drm/amd: check num of link levels when update pcie param (bsc#1225564).
    - CVE-2023-52857: drm/mediatek: Fix coverity issue with unintentional integer overflow (bsc#1225581).
    - CVE-2023-52863: hwmon: (axi-fan-control) Fix possible NULL pointer dereference (bsc#1225586).
    - CVE-2024-26585: Fixed race between tx work scheduling and socket close (bsc#1220187).
    - CVE-2024-26615: net/smc: fix illegal rmb_desc access in SMC-D connection dump (bsc#1220942).
    - CVE-2024-26633: ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (bsc#1221647).
    - CVE-2024-26635: llc: Drop support for ETH_P_TR_802_2 (bsc#1221656).
    - CVE-2024-26636: llc: make llc_ui_sendmsg() more robust against bonding changes (bsc#1221659).
    - CVE-2024-26641: ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv() (bsc#1221654).
    - CVE-2024-26661: drm/amd/display: Add NULL test for 'timing generator' in (bsc#1222323)
    - CVE-2024-26663: tipc: Check the bearer type before calling tipc_udp_nl_bearer_add() (bsc#1222326).
    - CVE-2024-26665: tunnels: fix out of bounds access when building IPv6 PMTU error (bsc#1222328).
    - CVE-2024-26802: stmmac: Clear variable when destroying workqueue (bsc#1222799).
    - CVE-2024-26863: hsr: Fix uninit-value access in hsr_get_node() (bsc#1223021).
    - CVE-2024-26961: mac802154: fix llsec key resources release in mac802154_llsec_key_del (bsc#1223652).
    - CVE-2024-27015: netfilter: flowtable: incorrect pppoe tuple (bsc#1223806).
    - CVE-2024-27019: netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (bsc#1223813)
    - CVE-2024-27020: netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (bsc#1223815)
    - CVE-2024-27025: nbd: null check for nla_nest_start (bsc#1223778)
    - CVE-2024-27065: netfilter: nf_tables: do not compare internal table flags on updates (bsc#1223836).
    - CVE-2024-27402: phonet/pep: fix racy skb_queue_empty() use (bsc#1224414).
    - CVE-2024-27437: vfio/pci: Disable auto-enable of exclusive INTx IRQ (bsc#1222625).
    - CVE-2024-35805: dm snapshot: fix lockup in dm_exception_table_exit (bsc#1224743).
    - CVE-2024-35819: soc: fsl: qbman: Use raw spinlock for cgr_lock (bsc#1224683).
    - CVE-2024-35837: net: mvpp2: clear BM pool before initialization (bsc#1224500).
    - CVE-2024-35853: mlxsw: spectrum_acl_tcam: Fix memory leak during rehash (bsc#1224604).
    - CVE-2024-35889: idpf: fix kernel panic on unknown packet types (bsc#1224517).
    - CVE-2024-35890: gro: fix ownership transfer (bsc#1224516).
    - CVE-2024-35893: net/sched: act_skbmod: prevent kernel-infoleak (bsc#1224512)
    - CVE-2024-35899: netfilter: nf_tables: flush pending destroy work before exit_net release (bsc#1224499)
    - CVE-2024-35934: net/smc: reduce rtnl pressure in smc_pnet_create_pnetids_list() (bsc#1224641)
    - CVE-2024-35949: btrfs: make sure that WRITTEN is set on all metadata blocks (bsc#1224700)
    - CVE-2024-35961: net/mlx5: Restore mistakenly dropped parts in register devlink flow (bsc#1224585).
    - CVE-2024-35995: ACPI: CPPC: Fix access width used for PCC registers (bsc#1224557).
    - CVE-2024-36000: mm/hugetlb: fix missing hugetlb_lock for resv uncharge (bsc#1224548).
    - CVE-2024-36004: i40e: Do not use WQ_MEM_RECLAIM flag for workqueue (bsc#1224545)
    - CVE-2024-36901: ipv6: prevent NULL dereference in ip6_output() (bsc#1225711)
    - CVE-2024-36902: ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action() (bsc#1225719).
    - CVE-2024-36909: Drivers: hv: vmbus: Do not free ring buffers that couldn't be re-encrypted
    (bsc#1225744).
    - CVE-2024-36910: uio_hv_generic: Do not free decrypted memory (bsc#1225717).
    - CVE-2024-36911: hv_netvsc: Do not free decrypted memory (bsc#1225745).
    - CVE-2024-36912: Drivers: hv: vmbus: Track decrypted status in vmbus_gpadl (bsc#1225752).
    - CVE-2024-36913: Drivers: hv: vmbus: Leak pages if set_memory_encrypted() fails (bsc#1225753).
    - CVE-2024-36914: drm/amd/display: Skip on writeback when it's not applicable (bsc#1225757).
    - CVE-2024-36919: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload (bsc#1225767).
    - CVE-2024-36923: fs/9p: fix uninitialized values during inode evict (bsc#1225815).
    - CVE-2024-36939: nfs: Handle error of rpc_proc_register() in nfs_net_init() (bsc#1225838).
    - CVE-2024-36946: phonet: fix rtm_phonet_notify() skb allocation (bsc#1225851).
    - CVE-2024-36974: net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP (bsc#1226519).
    - CVE-2024-38555: net/mlx5: Discard command completions in internal error (bsc#1226607).
    - CVE-2024-38558: net: openvswitch: fix overwriting ct original tuple for ICMPv6 (bsc#1226783).
    - CVE-2024-38570: gfs2: Fix potential glock use-after-free on unmount (bsc#1226775).
    - CVE-2024-38586: r8169: Fix possible ring buffer corruption on fragmented Tx packets (bsc#1226750).
    - CVE-2024-38598: md: fix resync softlockup when bitmap size is less than array size (bsc#1226757).
    - CVE-2024-38628: usb: gadget: u_audio: Fix race condition use of controls after free during gadget unbind
    (bsc#1226911).
    - CVE-2024-39276: ext4: fix mb_cache_entry's e_refcnt leak in ext4_xattr_block_cache_find() (bsc#1226993).
    - CVE-2024-39371: io_uring: check for non-NULL file pointer in io_file_can_poll() (bsc#1226990).
    - CVE-2024-39463: 9p: add missing locking around taking dentry fid list (bsc#1227090).
    - CVE-2024-39472: xfs: fix log recovery buffer allocation for the legacy h_size fixup (bsc#1227432).
    - CVE-2024-39482: bcache: fix variable length array abuse in btree_iter (bsc#1227447).
    - CVE-2024-39487: bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (bsc#1227573)
    - CVE-2024-39490: ipv6: sr: fix missing sk_buff release in seg6_input_core (bsc#1227626).
    - CVE-2024-39493: crypto: qat - Fix ADF_DEV_RESET_SYNC memory leak (bsc#1227620).
    - CVE-2024-39494: ima: Fix use-after-free on a dentry's dname.name (bsc#1227716).
    - CVE-2024-39497: drm/shmem-helper: Fix BUG_ON() on mmap(PROT_WRITE, MAP_PRIVATE) (bsc#1227722)
    - CVE-2024-39502: ionic: fix use after netif_napi_del() (bsc#1227755).
    - CVE-2024-39506: liquidio: Adjust a NULL pointer handling path in lio_vf_rep_copy_packet (bsc#1227729).
    - CVE-2024-39507: net: hns3: fix kernel crash problem in concurrent scenario (bsc#1227730).
    - CVE-2024-39508: io_uring/io-wq: Use set_bit() and test_bit() at worker->flags (bsc#1227732).
    - CVE-2024-40901: scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (bsc#1227762).
    - CVE-2024-40906: net/mlx5: Always stop health timer during driver removal (bsc#1227763).
    - CVE-2024-40908: bpf: Set run context for rawtp test_run callback (bsc#1227783).
    - CVE-2024-40909: bpf: Fix a potential use-after-free in bpf_link_free() (bsc#1227798).
    - CVE-2024-40919: bnxt_en: Adjust logging of firmware messages in case of released token in __hwrm_send()
    (bsc#1227779).
    - CVE-2024-40923: vmxnet3: disable rx data ring on dma allocation failure (bsc#1227786).
    - CVE-2024-40931: mptcp: ensure snd_una is properly initialized on connect (bsc#1227780).
    - CVE-2024-40935: cachefiles: flush all requests after setting CACHEFILES_DEAD (bsc#1227797).
    - CVE-2024-40937: gve: Clear napi->skb before dev_kfree_skb_any() (bsc#1227836).
    - CVE-2024-40940: net/mlx5: Fix tainted pointer delete is case of flow rules creation fail (bsc#1227800).
    - CVE-2024-40943: ocfs2: fix races between hole punching and AIO+DIO (bsc#1227849).
    - CVE-2024-40953: KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin() (bsc#1227806).
    - CVE-2024-40954: net: do not leave a dangling sk pointer, when socket creation fails (bsc#1227808)
    - CVE-2024-40958: netns: Make get_net_ns() handle zero refcount net (bsc#1227812).
    - CVE-2024-40959: xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr() (bsc#1227884).
    - CVE-2024-40960: ipv6: prevent possible NULL dereference in rt6_probe() (bsc#1227813).
    - CVE-2024-40961: ipv6: prevent possible NULL deref in fib6_nh_init() (bsc#1227814).
    - CVE-2024-40966: kABI: tty: add the option to have a tty reject a new ldisc (bsc#1227886).
    - CVE-2024-40967: serial: imx: Introduce timeout when waiting on transmitter empty (bsc#1227891).
    - CVE-2024-40970: Avoid hw_desc array overrun in dw-axi-dmac (bsc#1227899).
    - CVE-2024-40972: ext4: fold quota accounting into ext4_xattr_inode_lookup_create() (bsc#1227910).
    - CVE-2024-40977: wifi: mt76: mt7921s: fix potential hung tasks during chip recovery (bsc#1227950).
    - CVE-2024-40982: ssb: Fix potential NULL pointer dereference in ssb_device_uevent() (bsc#1227865).
    - CVE-2024-40989: KVM: arm64: Disassociate vcpus from redistributor region on teardown (bsc#1227823).
    - CVE-2024-40994: ptp: fix integer overflow in max_vclocks_store (bsc#1227829).
    - CVE-2024-40998: ext4: fix uninitialized ratelimit_state->lock access in __ext4_fill_super()
    (bsc#1227866).
    - CVE-2024-40999: net: ena: Add validation for completion descriptors consistency (bsc#1227913).
    - CVE-2024-41006: netrom: Fix a memory leak in nr_heartbeat_expiry() (bsc#1227862).
    - CVE-2024-41009: selftests/bpf: Add more ring buffer test coverage (bsc#1228020).
    - CVE-2024-41012: filelock: Remove locks reliably when fcntl/close race is detected (bsc#1228247).
    - CVE-2024-41013: xfs: do not walk off the end of a directory data block (bsc#1228405).
    - CVE-2024-41014: xfs: add bounds checking to xlog_recover_process_data (bsc#1228408).
    - CVE-2024-41015: ocfs2: add bounds checking to ocfs2_check_dir_entry() (bsc#1228409).
    - CVE-2024-41016: ocfs2: add bounds checking to ocfs2_xattr_find_entry() (bsc#1228410).
    - CVE-2024-41017: jfs: do not walk off the end of ealist (bsc#1228403).
    - CVE-2024-41040: net/sched: Fix UAF when resolving a clash (bsc#1228518)
    - CVE-2024-41041: udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port() (bsc#1228520)
    - CVE-2024-41044: ppp: reject claimed-as-LCP but actually malformed packets (bsc#1228530).
    - CVE-2024-41048: skmsg: Skip zero length skb in sk_msg_recvmsg (bsc#1228565)
    - CVE-2024-41057: cachefiles: fix slab-use-after-free in cachefiles_withdraw_cookie() (bsc#1228462).
    - CVE-2024-41058: cachefiles: fix slab-use-after-free in fscache_withdraw_volume() (bsc#1228459).
    - CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228561).
    - CVE-2024-41063: Bluetooth: hci_core: cancel all works upon hci_unregister_dev() (bsc#1228580)
    - CVE-2024-41064: powerpc/eeh: avoid possible crash when edev->pdev changes (bsc#1228599).
    - CVE-2024-41066: ibmvnic: Add tx check to prevent skb leak (bsc#1228640).
    - CVE-2024-41069: ASoC: topology: Fix route memory corruption (bsc#1228644).
    - CVE-2024-41070: KVM: PPC: Book3S HV: Prevent UAF in kvm_spapr_tce_attach_iommu_group() (bsc#1228581).
    - CVE-2024-41071: wifi: mac80211: Avoid address calculations via out of bounds array indexing
    (bsc#1228625).
    - CVE-2024-41078: btrfs: qgroup: fix quota root leak after quota disable failure (bsc#1228655).
    - CVE-2024-41081: ila: block BH in ila_output() (bsc#1228617)
    - CVE-2024-41090: tap: add missing verification for short frame (bsc#1228328).
    - CVE-2024-41091: tun: add missing verification for short frame (bsc#1228327).
    - CVE-2024-42070: netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers
    (bsc#1228470)
    - CVE-2024-42079: gfs2: Fix NULL pointer dereference in gfs2_log_flush (bsc#1228672).
    - CVE-2024-42093: net/dpaa2: Avoid explicit cpumask var allocation on stack (bsc#1228680).
    - CVE-2024-42096: x86: stop playing stack games in profile_pc() (bsc#1228633).
    - CVE-2024-42122: drm/amd/display: Add NULL pointer check for kzalloc (bsc#1228591)
    - CVE-2024-42124: scsi: qedf: Make qedf_execute_tmf() non-preemptible (bsc#1228705)
    - CVE-2024-42145: IB/core: Implement a limit on UMAD receive List (bsc#1228743)
    - CVE-2024-42161: bpf: Avoid uninitialized value in BPF_CORE_READ_BITFIELD (bsc#1228756).
    - CVE-2024-42224: net: dsa: mv88e6xxx: Correct check for empty list (bsc#1228723)
    - CVE-2024-42230: powerpc/pseries: Fix scv instruction crash with kexec (bsc#1194869).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228857");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036488.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47186");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47547");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47624");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48797");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48824");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-37453");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52573");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39371");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39499");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41040");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42122");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42230");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42093");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.63.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.63.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.63.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.63.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.63.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-vdso-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.63.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.63.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.63.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / etc');
}
