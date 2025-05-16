#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2802-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205163);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id(
    "CVE-2023-38417",
    "CVE-2023-47210",
    "CVE-2023-51780",
    "CVE-2023-52435",
    "CVE-2023-52472",
    "CVE-2023-52751",
    "CVE-2023-52775",
    "CVE-2024-25741",
    "CVE-2024-26615",
    "CVE-2024-26623",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26641",
    "CVE-2024-26663",
    "CVE-2024-26665",
    "CVE-2024-26691",
    "CVE-2024-26734",
    "CVE-2024-26785",
    "CVE-2024-26826",
    "CVE-2024-26863",
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
    "CVE-2024-35805",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35890",
    "CVE-2024-35893",
    "CVE-2024-35899",
    "CVE-2024-35908",
    "CVE-2024-35934",
    "CVE-2024-35942",
    "CVE-2024-36003",
    "CVE-2024-36004",
    "CVE-2024-36889",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36909",
    "CVE-2024-36910",
    "CVE-2024-36911",
    "CVE-2024-36912",
    "CVE-2024-36913",
    "CVE-2024-36914",
    "CVE-2024-36922",
    "CVE-2024-36930",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36942",
    "CVE-2024-36944",
    "CVE-2024-36946",
    "CVE-2024-36947",
    "CVE-2024-36949",
    "CVE-2024-36950",
    "CVE-2024-36951",
    "CVE-2024-36955",
    "CVE-2024-36959",
    "CVE-2024-36974",
    "CVE-2024-38558",
    "CVE-2024-38586",
    "CVE-2024-38598",
    "CVE-2024-38604",
    "CVE-2024-38659",
    "CVE-2024-39276",
    "CVE-2024-39468",
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
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2802-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:2802-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:2802-1 advisory.

    The SUSE Linux Enterprise 15 SP6 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2023-47210: wifi: iwlwifi: bump FW API to 90 for BZ/SC devices (bsc#1225601, bsc#1225600).
    - CVE-2023-52435: net: prevent mss overflow in skb_segment() (bsc#1220138).
    - CVE-2023-52751: smb: client: fix use-after-free in smb2_query_info_compound() (bsc#1225489).
    - CVE-2023-52775: net/smc: avoid data corruption caused by decline (bsc#1225088).
    - CVE-2024-26615: net/smc: fix illegal rmb_desc access in SMC-D connection dump (bsc#1220942).
    - CVE-2024-26623: pds_core: Prevent race issues involving the adminq (bsc#1221057).
    - CVE-2024-26633: ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (bsc#1221647).
    - CVE-2024-26635: llc: Drop support for ETH_P_TR_802_2 (bsc#1221656).
    - CVE-2024-26636: llc: make llc_ui_sendmsg() more robust against bonding changes (bsc#1221659).
    - CVE-2024-26641: ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv() (bsc#1221654).
    - CVE-2024-26663: tipc: Check the bearer type before calling tipc_udp_nl_bearer_add() (bsc#1222326).
    - CVE-2024-26665: tunnels: fix out of bounds access when building IPv6 PMTU error (bsc#1222328).
    - CVE-2024-26691: KVM: arm64: Fix circular locking dependency (bsc#1222463).
    - CVE-2024-26734: devlink: fix possible use-after-free and memory leaks in devlink_init() (bsc#1222438).
    - CVE-2024-26785: iommufd: Fix protection fault in iommufd_test_syz_conv_iova (bsc#1222779).
    - CVE-2024-26826: mptcp: fix data re-injection from stale subflow (bsc#1223010).
    - CVE-2024-26863: hsr: Fix uninit-value access in hsr_get_node() (bsc#1223021).
    - CVE-2024-26944: btrfs: zoned: fix lock ordering in btrfs_zone_activate() (bsc#1223731).
    - CVE-2024-27012: netfilter: nf_tables: restore set elements when delete set fails (bsc#1223804).
    - CVE-2024-27015: netfilter: flowtable: incorrect pppoe tuple (bsc#1223806).
    - CVE-2024-27016: netfilter: flowtable: validate pppoe header (bsc#1223807).
    - CVE-2024-27019: netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (bsc#1223813)
    - CVE-2024-27020: netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (bsc#1223815)
    - CVE-2024-27025: nbd: null check for nla_nest_start (bsc#1223778)
    - CVE-2024-27064: netfilter: nf_tables: Fix a memory leak in nf_tables_updchain (bsc#1223740).
    - CVE-2024-27065: netfilter: nf_tables: do not compare internal table flags on updates (bsc#1223836).
    - CVE-2024-27402: phonet/pep: fix racy skb_queue_empty() use (bsc#1224414).
    - CVE-2024-27404: mptcp: fix data races on remote_id (bsc#1224422)
    - CVE-2024-35805: dm snapshot: fix lockup in dm_exception_table_exit (bsc#1224743).
    - CVE-2024-35853: mlxsw: spectrum_acl_tcam: Fix memory leak during rehash (bsc#1224604).
    - CVE-2024-35854: Fixed possible use-after-free during rehash (bsc#1224636).
    - CVE-2024-35890: gro: fix ownership transfer (bsc#1224516).
    - CVE-2024-35893: net/sched: act_skbmod: prevent kernel-infoleak (bsc#1224512)
    - CVE-2024-35899: netfilter: nf_tables: flush pending destroy work before exit_net release (bsc#1224499)
    - CVE-2024-35908: tls: get psock ref after taking rxlock to avoid leak (bsc#1224490)
    - CVE-2024-35934: net/smc: reduce rtnl pressure in smc_pnet_create_pnetids_list() (bsc#1224641)
    - CVE-2024-35942: pmdomain: imx8mp-blk-ctrl: imx8mp_blk: Add fdcc clock to hdmimix domain (bsc#1224589).
    - CVE-2024-36003: ice: fix LAG and VF lock dependency in ice_reset_vf() (bsc#1224544).
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
    - CVE-2024-36946: phonet: fix rtm_phonet_notify() skb allocation (bsc#1225851).
    - CVE-2024-36974: net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP (bsc#1226519).
    - CVE-2024-38558: net: openvswitch: fix overwriting ct original tuple for ICMPv6 (bsc#1226783).
    - CVE-2024-38586: r8169: Fix possible ring buffer corruption on fragmented Tx packets (bsc#1226750).
    - CVE-2024-38598: md: fix resync softlockup when bitmap size is less than array size (bsc#1226757).
    - CVE-2024-38604: block: refine the EOF check in blkdev_iomap_begin (bsc#1226866).
    - CVE-2024-38659: enic: Validate length of nl attributes in enic_set_vf_port (bsc#1226883).
    - CVE-2024-39276: ext4: fix mb_cache_entry's e_refcnt leak in ext4_xattr_block_cache_find() (bsc#1226993).
    - CVE-2024-39468: smb: client: fix deadlock in smb2_find_smb_tcon() (bsc#1227103.
    - CVE-2024-39472: xfs: fix log recovery buffer allocation for the legacy h_size fixup (bsc#1227432).
    - CVE-2024-39474: mm/vmalloc: fix vmalloc which may return null if called with __GFP_NOFAIL (bsc#1227434).
    - CVE-2024-39482: bcache: fix variable length array abuse in btree_iter (bsc#1227447).
    - CVE-2024-39487: bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (bsc#1227573)
    - CVE-2024-39490: ipv6: sr: fix missing sk_buff release in seg6_input_core (bsc#1227626).
    - CVE-2024-39494: ima: Fix use-after-free on a dentry's dname.name (bsc#1227716).
    - CVE-2024-39496: btrfs: zoned: fix use-after-free due to race with dev replace (bsc#1227719).
    - CVE-2024-39498: drm/mst: Fix NULL pointer dereference at drm_dp_add_payload_part2 (bsc#1227723)
    - CVE-2024-39502: ionic: fix use after netif_napi_del() (bsc#1227755).
    - CVE-2024-39504: netfilter: nft_inner: validate mandatory meta and payload (bsc#1227757).
    - CVE-2024-39507: net: hns3: fix kernel crash problem in concurrent scenario (bsc#1227730).
    - CVE-2024-40901: scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (bsc#1227762).
    - CVE-2024-40906: net/mlx5: Always stop health timer during driver removal (bsc#1227763).
    - CVE-2024-40908: bpf: Set run context for rawtp test_run callback (bsc#1227783).
    - CVE-2024-40919: bnxt_en: Adjust logging of firmware messages in case of released token in __hwrm_send()
    (bsc#1227779).
    - CVE-2024-40923: vmxnet3: disable rx data ring on dma allocation failure (bsc#1227786).
    - CVE-2024-40925: block: fix request.queuelist usage in flush (bsc#1227789).
    - CVE-2024-40928: net: ethtool: fix the error condition in ethtool_get_phy_stats_ethtool() (bsc#1227788).
    - CVE-2024-40931: mptcp: ensure snd_una is properly initialized on connect (bsc#1227780).
    - CVE-2024-40935: cachefiles: flush all requests after setting CACHEFILES_DEAD (bsc#1227797).
    - CVE-2024-40937: gve: Clear napi->skb before dev_kfree_skb_any() (bsc#1227836).
    - CVE-2024-40940: net/mlx5: Fix tainted pointer delete is case of flow rules creation fail (bsc#1227800).
    - CVE-2024-40947: ima: Avoid blocking in RCU read-side critical section (bsc#1227803).
    - CVE-2024-40948: mm/page_table_check: fix crash on ZONE_DEVICE (bsc#1227801).
    - CVE-2024-40953: KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin() (bsc#1227806).
    - CVE-2024-40960: ipv6: prevent possible NULL dereference in rt6_probe() (bsc#1227813).
    - CVE-2024-40961: ipv6: prevent possible NULL deref in fib6_nh_init() (bsc#1227814).
    - CVE-2024-40966: kABI: tty: add the option to have a tty reject a new ldisc (bsc#1227886).
    - CVE-2024-40970: Avoid hw_desc array overrun in dw-axi-dmac (bsc#1227899).
    - CVE-2024-40972: ext4: fold quota accounting into ext4_xattr_inode_lookup_create() (bsc#1227910).
    - CVE-2024-40975: platform/x86: x86-android-tablets: Unregister devices in reverse order (bsc#1227926).
    - CVE-2024-40998: ext4: fix uninitialized ratelimit_state->lock access in __ext4_fill_super()
    (bsc#1227866).
    - CVE-2024-40999: net: ena: Add validation for completion descriptors consistency (bsc#1227913).
    - CVE-2024-41006: netrom: Fix a memory leak in nr_heartbeat_expiry() (bsc#1227862).
    - CVE-2024-41013: xfs: do not walk off the end of a directory data block (bsc#1228405).
    - CVE-2024-41014: xfs: add bounds checking to xlog_recover_process_data (bsc#1228408).
    - CVE-2024-41017: jfs: do not walk off the end of ealist (bsc#1228403).
    - CVE-2024-41090: tap: add missing verification for short frame (bsc#1228328).
    - CVE-2024-41091: tun: add missing verification for short frame (bsc#1228327).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223021");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227149");
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
  # https://lists.suse.com/pipermail/sle-security-updates/2024-August/019133.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ac05c5f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26863");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39468");
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
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41011");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/08");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-6_4_0-150600_23_17-default");
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
    {'reference':'kernel-64kb-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'cluster-md-kmp-64kb-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-default-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-64kb-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-default-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-allwinner-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-altera-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amazon-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amd-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amlogic-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-apm-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-apple-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-arm-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-broadcom-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-cavium-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-exynos-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-freescale-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-hisilicon-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-lg-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-marvell-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-mediatek-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-nvidia-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-qcom-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-renesas-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-rockchip-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-socionext-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-sprd-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-xilinx-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-64kb-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-default-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-extra-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-livepatch-devel-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-optional-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-devel-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-livepatch-devel-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-vdso-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.17.1.150600.12.6.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-rebuild-6.4.0-150600.23.17.1.150600.12.6.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-rebuild-6.4.0-150600.23.17.1.150600.12.6.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-livepatch-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-livepatch-devel-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-optional-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-vdso-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-devel-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-devel-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-livepatch-devel-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-livepatch-devel-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-vdso-6.4.0-150600.23.17.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-obs-qa-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-vanilla-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.17.1', 'cpu':'s390x', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-64kb-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-default-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-64kb-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-default-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-64kb-6.4.0-150600.23.17.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'dlm-kmp-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'gfs2-kmp-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'ocfs2-kmp-default-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'kernel-default-livepatch-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-default-livepatch-devel-6.4.0-150600.23.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-livepatch-6_4_0-150600_23_17-default-1-150600.13.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.17.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-64kb / cluster-md-kmp-default / dlm-kmp-64kb / etc');
}
