#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2896-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205492);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id(
    "CVE-2021-47432",
    "CVE-2022-48772",
    "CVE-2023-38417",
    "CVE-2023-47210",
    "CVE-2023-51780",
    "CVE-2023-52435",
    "CVE-2023-52472",
    "CVE-2023-52622",
    "CVE-2023-52656",
    "CVE-2023-52672",
    "CVE-2023-52699",
    "CVE-2023-52735",
    "CVE-2023-52749",
    "CVE-2023-52750",
    "CVE-2023-52751",
    "CVE-2023-52753",
    "CVE-2023-52754",
    "CVE-2023-52757",
    "CVE-2023-52759",
    "CVE-2023-52762",
    "CVE-2023-52763",
    "CVE-2023-52764",
    "CVE-2023-52765",
    "CVE-2023-52766",
    "CVE-2023-52767",
    "CVE-2023-52768",
    "CVE-2023-52769",
    "CVE-2023-52773",
    "CVE-2023-52774",
    "CVE-2023-52775",
    "CVE-2023-52776",
    "CVE-2023-52777",
    "CVE-2023-52780",
    "CVE-2023-52781",
    "CVE-2023-52782",
    "CVE-2023-52783",
    "CVE-2023-52784",
    "CVE-2023-52786",
    "CVE-2023-52787",
    "CVE-2023-52788",
    "CVE-2023-52789",
    "CVE-2023-52791",
    "CVE-2023-52792",
    "CVE-2023-52794",
    "CVE-2023-52795",
    "CVE-2023-52796",
    "CVE-2023-52798",
    "CVE-2023-52799",
    "CVE-2023-52800",
    "CVE-2023-52801",
    "CVE-2023-52803",
    "CVE-2023-52804",
    "CVE-2023-52805",
    "CVE-2023-52806",
    "CVE-2023-52807",
    "CVE-2023-52808",
    "CVE-2023-52809",
    "CVE-2023-52810",
    "CVE-2023-52811",
    "CVE-2023-52812",
    "CVE-2023-52813",
    "CVE-2023-52814",
    "CVE-2023-52815",
    "CVE-2023-52816",
    "CVE-2023-52817",
    "CVE-2023-52818",
    "CVE-2023-52819",
    "CVE-2023-52821",
    "CVE-2023-52825",
    "CVE-2023-52826",
    "CVE-2023-52827",
    "CVE-2023-52829",
    "CVE-2023-52832",
    "CVE-2023-52833",
    "CVE-2023-52834",
    "CVE-2023-52835",
    "CVE-2023-52836",
    "CVE-2023-52837",
    "CVE-2023-52838",
    "CVE-2023-52840",
    "CVE-2023-52841",
    "CVE-2023-52842",
    "CVE-2023-52843",
    "CVE-2023-52844",
    "CVE-2023-52845",
    "CVE-2023-52846",
    "CVE-2023-52847",
    "CVE-2023-52849",
    "CVE-2023-52850",
    "CVE-2023-52851",
    "CVE-2023-52853",
    "CVE-2023-52854",
    "CVE-2023-52855",
    "CVE-2023-52856",
    "CVE-2023-52857",
    "CVE-2023-52858",
    "CVE-2023-52861",
    "CVE-2023-52862",
    "CVE-2023-52863",
    "CVE-2023-52864",
    "CVE-2023-52865",
    "CVE-2023-52866",
    "CVE-2023-52867",
    "CVE-2023-52868",
    "CVE-2023-52869",
    "CVE-2023-52870",
    "CVE-2023-52871",
    "CVE-2023-52872",
    "CVE-2023-52873",
    "CVE-2023-52874",
    "CVE-2023-52875",
    "CVE-2023-52876",
    "CVE-2023-52877",
    "CVE-2023-52878",
    "CVE-2023-52879",
    "CVE-2023-52880",
    "CVE-2023-52881",
    "CVE-2023-52883",
    "CVE-2023-52884",
    "CVE-2024-25741",
    "CVE-2024-26615",
    "CVE-2024-26623",
    "CVE-2024-26625",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26641",
    "CVE-2024-26663",
    "CVE-2024-26665",
    "CVE-2024-26676",
    "CVE-2024-26691",
    "CVE-2024-26734",
    "CVE-2024-26750",
    "CVE-2024-26758",
    "CVE-2024-26767",
    "CVE-2024-26780",
    "CVE-2024-26785",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26826",
    "CVE-2024-26845",
    "CVE-2024-26863",
    "CVE-2024-26889",
    "CVE-2024-26920",
    "CVE-2024-26944",
    "CVE-2024-27012",
    "CVE-2024-27015",
    "CVE-2024-27016",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27025",
    "CVE-2024-27064",
    "CVE-2024-27065",
    "CVE-2024-27402",
    "CVE-2024-27404",
    "CVE-2024-27414",
    "CVE-2024-27419",
    "CVE-2024-33619",
    "CVE-2024-34777",
    "CVE-2024-35247",
    "CVE-2024-35805",
    "CVE-2024-35807",
    "CVE-2024-35827",
    "CVE-2024-35831",
    "CVE-2024-35843",
    "CVE-2024-35848",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35857",
    "CVE-2024-35880",
    "CVE-2024-35884",
    "CVE-2024-35886",
    "CVE-2024-35890",
    "CVE-2024-35892",
    "CVE-2024-35893",
    "CVE-2024-35896",
    "CVE-2024-35898",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35908",
    "CVE-2024-35925",
    "CVE-2024-35926",
    "CVE-2024-35934",
    "CVE-2024-35942",
    "CVE-2024-35957",
    "CVE-2024-35962",
    "CVE-2024-35970",
    "CVE-2024-35976",
    "CVE-2024-35979",
    "CVE-2024-35998",
    "CVE-2024-36003",
    "CVE-2024-36004",
    "CVE-2024-36005",
    "CVE-2024-36008",
    "CVE-2024-36010",
    "CVE-2024-36017",
    "CVE-2024-36024",
    "CVE-2024-36281",
    "CVE-2024-36477",
    "CVE-2024-36478",
    "CVE-2024-36479",
    "CVE-2024-36882",
    "CVE-2024-36887",
    "CVE-2024-36889",
    "CVE-2024-36899",
    "CVE-2024-36900",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36903",
    "CVE-2024-36904",
    "CVE-2024-36909",
    "CVE-2024-36910",
    "CVE-2024-36911",
    "CVE-2024-36912",
    "CVE-2024-36913",
    "CVE-2024-36914",
    "CVE-2024-36915",
    "CVE-2024-36916",
    "CVE-2024-36917",
    "CVE-2024-36919",
    "CVE-2024-36922",
    "CVE-2024-36923",
    "CVE-2024-36924",
    "CVE-2024-36926",
    "CVE-2024-36930",
    "CVE-2024-36934",
    "CVE-2024-36935",
    "CVE-2024-36937",
    "CVE-2024-36938",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36942",
    "CVE-2024-36944",
    "CVE-2024-36945",
    "CVE-2024-36946",
    "CVE-2024-36947",
    "CVE-2024-36949",
    "CVE-2024-36950",
    "CVE-2024-36951",
    "CVE-2024-36952",
    "CVE-2024-36955",
    "CVE-2024-36957",
    "CVE-2024-36959",
    "CVE-2024-36960",
    "CVE-2024-36962",
    "CVE-2024-36964",
    "CVE-2024-36965",
    "CVE-2024-36967",
    "CVE-2024-36969",
    "CVE-2024-36971",
    "CVE-2024-36972",
    "CVE-2024-36973",
    "CVE-2024-36974",
    "CVE-2024-36975",
    "CVE-2024-36977",
    "CVE-2024-36978",
    "CVE-2024-37021",
    "CVE-2024-37078",
    "CVE-2024-37353",
    "CVE-2024-37354",
    "CVE-2024-38381",
    "CVE-2024-38384",
    "CVE-2024-38385",
    "CVE-2024-38388",
    "CVE-2024-38390",
    "CVE-2024-38391",
    "CVE-2024-38539",
    "CVE-2024-38540",
    "CVE-2024-38541",
    "CVE-2024-38543",
    "CVE-2024-38544",
    "CVE-2024-38545",
    "CVE-2024-38546",
    "CVE-2024-38547",
    "CVE-2024-38548",
    "CVE-2024-38549",
    "CVE-2024-38550",
    "CVE-2024-38551",
    "CVE-2024-38552",
    "CVE-2024-38553",
    "CVE-2024-38554",
    "CVE-2024-38555",
    "CVE-2024-38556",
    "CVE-2024-38557",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38560",
    "CVE-2024-38562",
    "CVE-2024-38564",
    "CVE-2024-38565",
    "CVE-2024-38566",
    "CVE-2024-38567",
    "CVE-2024-38568",
    "CVE-2024-38569",
    "CVE-2024-38570",
    "CVE-2024-38571",
    "CVE-2024-38572",
    "CVE-2024-38573",
    "CVE-2024-38575",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38580",
    "CVE-2024-38581",
    "CVE-2024-38582",
    "CVE-2024-38583",
    "CVE-2024-38586",
    "CVE-2024-38587",
    "CVE-2024-38588",
    "CVE-2024-38590",
    "CVE-2024-38591",
    "CVE-2024-38592",
    "CVE-2024-38594",
    "CVE-2024-38595",
    "CVE-2024-38597",
    "CVE-2024-38598",
    "CVE-2024-38599",
    "CVE-2024-38600",
    "CVE-2024-38601",
    "CVE-2024-38602",
    "CVE-2024-38603",
    "CVE-2024-38604",
    "CVE-2024-38605",
    "CVE-2024-38608",
    "CVE-2024-38610",
    "CVE-2024-38611",
    "CVE-2024-38615",
    "CVE-2024-38616",
    "CVE-2024-38617",
    "CVE-2024-38618",
    "CVE-2024-38619",
    "CVE-2024-38621",
    "CVE-2024-38622",
    "CVE-2024-38627",
    "CVE-2024-38628",
    "CVE-2024-38629",
    "CVE-2024-38630",
    "CVE-2024-38633",
    "CVE-2024-38634",
    "CVE-2024-38635",
    "CVE-2024-38636",
    "CVE-2024-38659",
    "CVE-2024-38661",
    "CVE-2024-38663",
    "CVE-2024-38664",
    "CVE-2024-38780",
    "CVE-2024-39276",
    "CVE-2024-39277",
    "CVE-2024-39291",
    "CVE-2024-39296",
    "CVE-2024-39301",
    "CVE-2024-39362",
    "CVE-2024-39371",
    "CVE-2024-39463",
    "CVE-2024-39466",
    "CVE-2024-39468",
    "CVE-2024-39469",
    "CVE-2024-39471",
    "CVE-2024-39472",
    "CVE-2024-39473",
    "CVE-2024-39474",
    "CVE-2024-39475",
    "CVE-2024-39479",
    "CVE-2024-39481",
    "CVE-2024-39482",
    "CVE-2024-39487",
    "CVE-2024-39490",
    "CVE-2024-39494",
    "CVE-2024-39496",
    "CVE-2024-39498",
    "CVE-2024-39502",
    "CVE-2024-39504",
    "CVE-2024-39507",
    "CVE-2024-40901",
    "CVE-2024-40906",
    "CVE-2024-40908",
    "CVE-2024-40919",
    "CVE-2024-40923",
    "CVE-2024-40925",
    "CVE-2024-40928",
    "CVE-2024-40931",
    "CVE-2024-40935",
    "CVE-2024-40937",
    "CVE-2024-40940",
    "CVE-2024-40947",
    "CVE-2024-40948",
    "CVE-2024-40953",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40966",
    "CVE-2024-40970",
    "CVE-2024-40972",
    "CVE-2024-40975",
    "CVE-2024-40979",
    "CVE-2024-40998",
    "CVE-2024-40999",
    "CVE-2024-41006",
    "CVE-2024-41011",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-41017",
    "CVE-2024-41090",
    "CVE-2024-41091"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2896-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:2896-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:2896-1 advisory.

    The SUSE Linux Enterprise 15 SP6 Azure kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-41014: xfs: add bounds checking to xlog_recover_process_data (bsc#1228408).
    - CVE-2024-41013: xfs: do not walk off the end of a directory data block (bsc#1228405).
    - CVE-2024-41017: jfs: do not walk off the end of ealist (bsc#1228403).
    - CVE-2024-40972: ext4: fold quota accounting into ext4_xattr_inode_lookup_create() (bsc#1227910).
    - CVE-2024-39276: ext4: fix mb_cache_entry's e_refcnt leak in ext4_xattr_block_cache_find() (bsc#1226993).
    - CVE-2024-40925: block: fix request.queuelist usage in flush (bsc#1227789).
    - CVE-2024-40998: ext4: fix uninitialized ratelimit_state->lock access in __ext4_fill_super()
    (bsc#1227866).
    - CVE-2024-39494: ima: Fix use-after-free on a dentry's dname.name (bsc#1227716).
    - CVE-2024-39496: btrfs: zoned: fix use-after-free due to race with dev replace (bsc#1227719).
    - CVE-2024-41091: tun: add missing verification for short frame (bsc#1228327).
    - CVE-2024-41090: tap: add missing verification for short frame (bsc#1228328).
    - CVE-2024-40999: net: ena: Add validation for completion descriptors consistency (bsc#1227913).
    - CVE-2024-40966: kABI: tty: add the option to have a tty reject a new ldisc (bsc#1227886).
    - CVE-2024-40975: platform/x86: x86-android-tablets: Unregister devices in reverse order (bsc#1227926).
    - CVE-2024-40970: Avoid hw_desc array overrun in dw-axi-dmac (bsc#1227899).
    - CVE-2024-40947: ima: Avoid blocking in RCU read-side critical section (bsc#1227803).
    - CVE-2024-40908: bpf: Set run context for rawtp test_run callback (bsc#1227783).
    - CVE-2024-40960: ipv6: prevent possible NULL dereference in rt6_probe() (bsc#1227813).
    - CVE-2024-40935: cachefiles: flush all requests after setting CACHEFILES_DEAD (bsc#1227797).
    - CVE-2024-40961: ipv6: prevent possible NULL deref in fib6_nh_init() (bsc#1227814).
    - CVE-2024-39504: netfilter: nft_inner: validate mandatory meta and payload (bsc#1227757).
    - CVE-2024-41006: netrom: Fix a memory leak in nr_heartbeat_expiry() (bsc#1227862).
    - CVE-2024-40937: gve: Clear napi->skb before dev_kfree_skb_any() (bsc#1227836).
    - CVE-2024-39507: net: hns3: fix kernel crash problem in concurrent scenario (bsc#1227730).
    - CVE-2024-40940: net/mlx5: Fix tainted pointer delete is case of flow rules creation fail (bsc#1227800).
    - CVE-2024-40928: net: ethtool: fix the error condition in ethtool_get_phy_stats_ethtool() (bsc#1227788).
    - CVE-2024-26944: btrfs: zoned: fix lock ordering in btrfs_zone_activate() (bsc#1223731).
    - CVE-2024-40923: vmxnet3: disable rx data ring on dma allocation failure (bsc#1227786).
    - CVE-2024-40931: mptcp: ensure snd_una is properly initialized on connect (bsc#1227780).
    - CVE-2024-40919: bnxt_en: Adjust logging of firmware messages in case of released token in __hwrm_send()
    (bsc#1227779).
    - CVE-2024-39487: bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (bsc#1227573)
    - CVE-2024-35908: tls: get psock ref after taking rxlock to avoid leak (bsc#1224490)
    - CVE-2024-35899: netfilter: nf_tables: flush pending destroy work before exit_net release (bsc#1224499)
    - CVE-2024-35934: net/smc: reduce rtnl pressure in smc_pnet_create_pnetids_list() (bsc#1224641)
    - CVE-2024-35893: net/sched: act_skbmod: prevent kernel-infoleak (bsc#1224512)
    - CVE-2024-40901: scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (bsc#1227762).
    - CVE-2024-39472: xfs: fix log recovery buffer allocation for the legacy h_size fixup (bsc#1227432).
    - CVE-2024-40953: KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin() (bsc#1227806).
    - CVE-2024-27404: mptcp: fix data races on remote_id (bsc#1224422)
    - CVE-2024-27020: netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (bsc#1223815)
    - CVE-2024-27019: netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (bsc#1223813)
    - CVE-2024-40948: mm/page_table_check: fix crash on ZONE_DEVICE (bsc#1227801).
    - CVE-2024-35890: gro: fix ownership transfer (bsc#1224516).
    - CVE-2024-36902: ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action() (bsc#1225719).
    - CVE-2024-36946: phonet: fix rtm_phonet_notify() skb allocation (bsc#1225851).
    - CVE-2024-38586: r8169: Fix possible ring buffer corruption on fragmented Tx packets (bsc#1226750).
    - CVE-2024-39468: smb: client: fix deadlock in smb2_find_smb_tcon() (bsc#1227103.
    - CVE-2024-40906: net/mlx5: Always stop health timer during driver removal (bsc#1227763).
    - CVE-2024-27012: netfilter: nf_tables: restore set elements when delete set fails (bsc#1223804).
    - CVE-2024-39498: drm/mst: Fix NULL pointer dereference at drm_dp_add_payload_part2 (bsc#1227723)
    - CVE-2024-39502: ionic: fix use after netif_napi_del() (bsc#1227755).
    - CVE-2024-27016: netfilter: flowtable: validate pppoe header (bsc#1223807).
    - CVE-2024-36901: ipv6: prevent NULL dereference in ip6_output() (bsc#1225711)
    - CVE-2024-36004: i40e: Do not use WQ_MEM_RECLAIM flag for workqueue (bsc#1224545)
    - CVE-2024-27025: nbd: null check for nla_nest_start (bsc#1223778)
    - CVE-2024-35853: mlxsw: spectrum_acl_tcam: Fix memory leak during rehash (bsc#1224604).
    - CVE-2024-35854: Fixed possible use-after-free during rehash (bsc#1224636).
    - CVE-2024-27402: phonet/pep: fix racy skb_queue_empty() use (bsc#1224414).
    - CVE-2023-52435: net: prevent mss overflow in skb_segment() (bsc#1220138).
    - CVE-2024-27065: netfilter: nf_tables: do not compare internal table flags on updates (bsc#1223836).
    - CVE-2024-27015: netfilter: flowtable: incorrect pppoe tuple (bsc#1223806).
    - CVE-2024-27064: netfilter: nf_tables: Fix a memory leak in nf_tables_updchain (bsc#1223740).
    - CVE-2024-26663: tipc: Check the bearer type before calling tipc_udp_nl_bearer_add() (bsc#1222326).
    - CVE-2023-47210: wifi: iwlwifi: bump FW API to 90 for BZ/SC devices (bsc#1225601, bsc#1225600).
    - CVE-2023-52775: net/smc: avoid data corruption caused by decline (bsc#1225088).
    - CVE-2024-38558: net: openvswitch: fix overwriting ct original tuple for ICMPv6 (bsc#1226783).
    - CVE-2024-39490: ipv6: sr: fix missing sk_buff release in seg6_input_core (bsc#1227626).
    - CVE-2024-26826: mptcp: fix data re-injection from stale subflow (bsc#1223010).
    - CVE-2024-26615: net/smc: fix illegal rmb_desc access in SMC-D connection dump (bsc#1220942).
    - CVE-2024-35942: pmdomain: imx8mp-blk-ctrl: imx8mp_blk: Add fdcc clock to hdmimix domain (bsc#1224589).
    - CVE-2024-26691: KVM: arm64: Fix circular locking dependency (bsc#1222463).
    - CVE-2024-36909: Drivers: hv: vmbus: Do not free ring buffers that couldn't be re-encrypted
    (bsc#1225744).
    - CVE-2024-36910: uio_hv_generic: Do not free decrypted memory (bsc#1225717).
    - CVE-2024-36911: hv_netvsc: Do not free decrypted memory (bsc#1225745).
    - CVE-2024-36912: Drivers: hv: vmbus: Track decrypted status in vmbus_gpadl (bsc#1225752).
    - CVE-2024-36913: Drivers: hv: vmbus: Leak pages if set_memory_encrypted() fails (bsc#1225753).
    - CVE-2024-26665: tunnels: fix out of bounds access when building IPv6 PMTU error (bsc#1222328).
    - CVE-2024-38659: enic: Validate length of nl attributes in enic_set_vf_port (bsc#1226883).
    - CVE-2023-52751: smb: client: fix use-after-free in smb2_query_info_compound() (bsc#1225489).
    - CVE-2024-39482: bcache: fix variable length array abuse in btree_iter (bsc#1227447).
    - CVE-2024-39474: mm/vmalloc: fix vmalloc which may return null if called with __GFP_NOFAIL (bsc#1227434).
    - CVE-2024-26636: llc: make llc_ui_sendmsg() more robust against bonding changes (bsc#1221659).
    - CVE-2024-26635: llc: Drop support for ETH_P_TR_802_2 (bsc#1221656).
    - CVE-2024-38598: md: fix resync softlockup when bitmap size is less than array size (bsc#1226757).
    - CVE-2024-36003: ice: fix LAG and VF lock dependency in ice_reset_vf() (bsc#1224544).
    - CVE-2024-38604: block: refine the EOF check in blkdev_iomap_begin (bsc#1226866).
    - CVE-2024-26641: ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv() (bsc#1221654).
    - CVE-2024-26863: hsr: Fix uninit-value access in hsr_get_node() (bsc#1223021).
    - CVE-2024-26633: ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (bsc#1221647).
    - CVE-2024-26623: pds_core: Prevent race issues involving the adminq (bsc#1221057).
    - CVE-2024-26785: iommufd: Fix protection fault in iommufd_test_syz_conv_iova (bsc#1222779).
    - CVE-2024-26734: devlink: fix possible use-after-free and memory leaks in devlink_init() (bsc#1222438).
    - CVE-2024-35805: dm snapshot: fix lockup in dm_exception_table_exit (bsc#1224743).
    - CVE-2024-39371: io_uring: check for non-NULL file pointer in io_file_can_poll() (bsc#1226990).
    - CVE-2023-52846: hsr: Prevent use after free in prp_create_tagged_frame() (bsc#1225098).
    - CVE-2024-38610: drivers/virt/acrn: fix PFNMAP PTE checks in acrn_vm_ram_map() (bsc#1226758).
    - CVE-2024-37354: btrfs: fix crash on racing fsync and size-extending write into prealloc (bsc#1227101).
    - CVE-2024-36919: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload (bsc#1225767).
    - CVE-2024-38559: scsi: qedf: Ensure the copied buf is NUL terminated (bsc#1226785).
    - CVE-2024-38570: gfs2: Fix potential glock use-after-free on unmount (bsc#1226775).
    - CVE-2024-36904: tcp: Use refcount_inc_not_zero() in tcp_twsk_unique() (bsc#1225732).
    - CVE-2023-52881: tcp: do not accept ACK of bytes we never sent (bsc#1225611).
    - CVE-2024-37353: virtio: fixed a double free in vp_del_vqs() (bsc#1226875).
    - CVE-2024-39301: net/9p: fix uninit-value in p9_client_rpc() (bsc#1226994).
    - CVE-2024-35843: iommu/vt-d: Use device rbtree in iopf reporting path (bsc#1224751).
    - CVE-2024-37078: nilfs2: fix potential kernel bug due to lack of writeback flag waiting (bsc#1227066).
    - CVE-2024-35247: fpga: region: add owner module and take its refcount (bsc#1226948).
    - CVE-2024-36479: fpga: bridge: add owner module and take its refcount (bsc#1226949).
    - CVE-2024-37021: fpga: manager: add owner module and take its refcount (bsc#1226950).
    - CVE-2024-36281: net/mlx5: Use mlx5_ipsec_rx_status_destroy to correctly delete status rules
    (bsc#1226799).
    - CVE-2024-38580: epoll: be better about file lifetimes (bsc#1226610).
    - CVE-2024-36478: null_blk: fix null-ptr-dereference while configuring 'power' and 'submit_queues'
    (bsc#1226841).
    - CVE-2024-38636: f2fs: multidev: fix to recognize valid zero block address (bsc#1226879).
    - CVE-2024-38661: s390/ap: Fix crash in AP internal function modify_bitmap() (bsc#1226996).
    - CVE-2024-38564: bpf: Add BPF_PROG_TYPE_CGROUP_SKB attach type enforcement in BPF_LINK_CREATE
    (bsc#1226789).
    - CVE-2024-38566: bpf: Fix verifier assumptions about socket->sk (bsc#1226790).
    - CVE-2024-38560: scsi: bfa: Ensure the copied buf is NUL terminated (bsc#1226786).
    - CVE-2024-36978: net: sched: sch_multiq: fix possible OOB write in multiq_tune() (bsc#1226514).
    - CVE-2024-36917: block: fix overflow in blk_ioctl_discard() (bsc#1225770).
    - CVE-2024-36974: net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP (bsc#1226519).
    - CVE-2024-38627: stm class: Fix a double free in stm_register_device() (bsc#1226857).
    - CVE-2024-38603: drivers/perf: hisi: hns3: Actually use devm_add_action_or_reset() (bsc#1226842).
    - CVE-2024-38553: net: fec: remove .ndo_poll_controller to avoid deadlock (bsc#1226744).
    - CVE-2024-38555: net/mlx5: Discard command completions in internal error (bsc#1226607).
    - CVE-2024-38556: net/mlx5: Add a timeout to acquire the command queue semaphore (bsc#1226774).
    - CVE-2024-38557: net/mlx5: Reload only IB representors upon lag disable/enable (bsc#1226781).
    - CVE-2024-38608: net/mlx5e: Fix netif state handling (bsc#1226746).
    - CVE-2024-38597: eth: sungem: remove .ndo_poll_controller to avoid deadlocks (bsc#1226749).
    - CVE-2024-38594: net: stmmac: move the EST lock to struct stmmac_priv (bsc#1226734).
    - CVE-2024-38569: drivers/perf: hisi_pcie: Fix out-of-bound access when valid event group (bsc#1226772).
    - CVE-2024-38568: drivers/perf: hisi: hns3: Fix out-of-bound access when valid event group (bsc#1226771).
    - CVE-2024-26814: vfio/fsl-mc: Block calling interrupt handler without trigger (bsc#1222810).
    - CVE-2024-26813: vfio/platform: Create persistent IRQ handlers (bsc#1222809).
    - CVE-2024-36945: net/smc: fix neighbour and rtable leak in smc_ib_find_route() (bsc#1225823).
    - CVE-2024-36923: fs/9p: fix uninitialized values during inode evict (bsc#1225815).
    - CVE-2024-36971: net: fix __dst_negative_advice() race (bsc#1226145).
    - CVE-2024-27414: rtnetlink: fix error logic of IFLA_BRIDGE_FLAGS writing back (bsc#1224439).
    - CVE-2024-35900: netfilter: nf_tables: reject new basechain after table flag update (bsc#1224497).
    - CVE-2024-35886: ipv6: Fix infinite recursion in fib6_dump_done() (bsc#1224670).
    - CVE-2024-36024: drm/amd/display: Disable idle reallow as part of command/gpint execution (bsc#1225702).
    - CVE-2024-36903: ipv6: Fix potential uninit-value access in __ip6_make_skb() (bsc#1225741).
    - CVE-2024-36914: drm/amd/display: Skip on writeback when it's not applicable (bsc#1225757).
    - CVE-2024-36899: gpiolib: cdev: Fix use after free in lineinfo_changed_notify (bsc#1225737).
    - CVE-2024-35979: raid1: fix use-after-free for original bio in raid1_write_request() (bsc#1224572).
    - CVE-2024-35807: ext4: fix corruption during on-line resize (bsc#1224735).
    - CVE-2023-52622: ext4: avoid online resizing failures due to oversized flex bg (bsc#1222080).
    - CVE-2023-52843: llc: verify mac len before reading mac header (bsc#1224951).
    - CVE-2024-35898: netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get()
    (bsc#1224498).
    - CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies (bsc#1225758).
    - CVE-2024-36017: rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation (bsc#1225681).
    - CVE-2024-36882: mm: use memalloc_nofs_save() in page_cache_ra_order() (bsc#1225723).
    - CVE-2024-36916: blk-iocost: avoid out of bounds shift (bsc#1225759).
    - CVE-2024-36900: net: hns3: fix kernel crash when devlink reload during initialization (bsc#1225726).
    - CVE-2023-52787: blk-mq: make sure active queue usage is held for bio_integrity_prep() (bsc#1225105).
    - CVE-2024-35925: block: prevent division by zero in blk_rq_stat_sum() (bsc#1224661).
    - CVE-2023-52837: nbd: fix uaf in nbd_open (bsc#1224935).
    - CVE-2023-52786: ext4: fix racy may inline data check in dio write (bsc#1224939).
    - CVE-2024-36934: bna: ensure the copied buf is NUL terminated (bsc#1225760).
    - CVE-2024-36935: ice: ensure the copied buf is NUL terminated (bsc#1225763).
    - CVE-2024-36937: xdp: use flags field to disambiguate broadcast redirect (bsc#1225834).
    - CVE-2023-52672: pipe: wakeup wr_wait after setting max_usage (bsc#1224614).
    - CVE-2023-52845: tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING (bsc#1225585).
    - CVE-2024-36005: netfilter: nf_tables: honor table dormant flag from netdev release event path
    (bsc#1224539).
    - CVE-2024-26845: scsi: target: core: Add TMF to tmr_list handling (bsc#1223018).
    - CVE-2024-35892: net/sched: fix lockdep splat in qdisc_tree_reduce_backlog() (bsc#1224515).
    - CVE-2024-35848: eeprom: at24: fix memory corruption race condition (bsc#1224612).
    - CVE-2024-35884: udp: do not accept non-tunnel GSO skbs landing in a tunnel (bsc#1224520).
    - CVE-2024-35857: icmp: prevent possible NULL dereferences from icmp_build_probe() (bsc#1224619).
    - CVE-2023-52735: bpf, sockmap: Don't let sock_map_{close,destroy,unhash} call itself (bsc#1225475).
    - CVE-2024-35926: crypto: iaa - Fix async_disable descriptor leak (bsc#1224655).
    - CVE-2024-35976: Validate user input for XDP_{UMEM|COMPLETION}_FILL_RING (bsc#1224575).
    - CVE-2024-36938: Fixed NULL pointer dereference in sk_psock_skb_ingress_enqueue (bsc#1225761).
    - CVE-2024-36008: ipv4: check for NULL idev in ip_route_use_hint() (bsc#1224540).
    - CVE-2024-35998: Fixed lock ordering potential deadlock in cifs_sync_mid_result (bsc#1224549).
    - CVE-2023-52757: Fixed potential deadlock when releasing mids (bsc#1225548).
    - CVE-2024-27419: Fixed data-races around sysctl_net_busy_read (bsc#1224759)
    - CVE-2024-36957: octeontx2-af: avoid off-by-one read from userspace (bsc#1225762).
    - CVE-2024-26625: Call sock_orphan() at release time (bsc#1221086)
    - CVE-2024-35880: io_uring/kbuf: hold io_buffer_list reference over mmap (bsc#1224523).
    - CVE-2024-35831: io_uring: Fix release of pinned pages when __io_uaddr_map fails (bsc#1224698).
    - CVE-2024-35827: io_uring/net: fix overflow check in io_recvmsg_mshot_prep() (bsc#1224606).
    - CVE-2023-52656: Dropped any code related to SCM_RIGHTS (bsc#1224187).
    - CVE-2023-52699: sysv: don't call sb_bread() with pointers_lock held (bsc#1224659).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228417");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-August/019185.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dded5262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27414");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-33619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38384");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38391");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38540");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38547");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38550");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38553");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38554");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38557");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38560");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38568");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38573");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39277");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39371");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39466");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39471");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41091");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41011");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/14");

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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-6.4.0-150600.8.8.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.8.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.8.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.8.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.8.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.8.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.8.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.8.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.8.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.8.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.8.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.8.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.8.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.8.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.8.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.8.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-devel / kernel-devel-azure / etc');
}
