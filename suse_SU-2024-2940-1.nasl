#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2940-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205735);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/26");

  script_cve_id(
    "CVE-2020-26558",
    "CVE-2021-0129",
    "CVE-2021-47191",
    "CVE-2021-47194",
    "CVE-2021-47197",
    "CVE-2021-47219",
    "CVE-2021-47295",
    "CVE-2021-47388",
    "CVE-2021-47395",
    "CVE-2021-47399",
    "CVE-2021-47403",
    "CVE-2021-47405",
    "CVE-2021-47438",
    "CVE-2021-47441",
    "CVE-2021-47468",
    "CVE-2021-47501",
    "CVE-2021-47516",
    "CVE-2021-47542",
    "CVE-2021-47559",
    "CVE-2021-47580",
    "CVE-2021-47582",
    "CVE-2021-47588",
    "CVE-2021-47597",
    "CVE-2021-47599",
    "CVE-2021-47606",
    "CVE-2021-47619",
    "CVE-2022-2964",
    "CVE-2022-20368",
    "CVE-2022-28748",
    "CVE-2022-48775",
    "CVE-2022-48792",
    "CVE-2022-48794",
    "CVE-2022-48804",
    "CVE-2022-48805",
    "CVE-2022-48810",
    "CVE-2022-48811",
    "CVE-2022-48823",
    "CVE-2022-48826",
    "CVE-2022-48827",
    "CVE-2022-48828",
    "CVE-2022-48829",
    "CVE-2022-48836",
    "CVE-2022-48839",
    "CVE-2022-48850",
    "CVE-2022-48855",
    "CVE-2022-48857",
    "CVE-2022-48860",
    "CVE-2022-48863",
    "CVE-2023-52435",
    "CVE-2023-52594",
    "CVE-2023-52612",
    "CVE-2023-52615",
    "CVE-2023-52619",
    "CVE-2023-52623",
    "CVE-2023-52669",
    "CVE-2023-52743",
    "CVE-2023-52885",
    "CVE-2024-26615",
    "CVE-2024-26659",
    "CVE-2024-26663",
    "CVE-2024-26735",
    "CVE-2024-26830",
    "CVE-2024-26920",
    "CVE-2024-26924",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27025",
    "CVE-2024-27437",
    "CVE-2024-35806",
    "CVE-2024-35819",
    "CVE-2024-35837",
    "CVE-2024-35887",
    "CVE-2024-35893",
    "CVE-2024-35934",
    "CVE-2024-35949",
    "CVE-2024-35966",
    "CVE-2024-35967",
    "CVE-2024-35978",
    "CVE-2024-35995",
    "CVE-2024-36004",
    "CVE-2024-36288",
    "CVE-2024-36592",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36919",
    "CVE-2024-36924",
    "CVE-2024-36939",
    "CVE-2024-36952",
    "CVE-2024-38558",
    "CVE-2024-38560",
    "CVE-2024-38630",
    "CVE-2024-39487",
    "CVE-2024-39488",
    "CVE-2024-39490",
    "CVE-2024-39494",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-39506",
    "CVE-2024-39507",
    "CVE-2024-39509",
    "CVE-2024-40901",
    "CVE-2024-40904",
    "CVE-2024-40912",
    "CVE-2024-40923",
    "CVE-2024-40929",
    "CVE-2024-40932",
    "CVE-2024-40937",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40953",
    "CVE-2024-40959",
    "CVE-2024-40966",
    "CVE-2024-40967",
    "CVE-2024-40978",
    "CVE-2024-40982",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40990",
    "CVE-2024-40995",
    "CVE-2024-40998",
    "CVE-2024-40999",
    "CVE-2024-41014",
    "CVE-2024-41015",
    "CVE-2024-41016",
    "CVE-2024-41044",
    "CVE-2024-41048",
    "CVE-2024-41059",
    "CVE-2024-41060",
    "CVE-2024-41063",
    "CVE-2024-41064",
    "CVE-2024-41066",
    "CVE-2024-41070",
    "CVE-2024-41071",
    "CVE-2024-41072",
    "CVE-2024-41078",
    "CVE-2024-41081",
    "CVE-2024-41089",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41095",
    "CVE-2024-42070",
    "CVE-2024-42093",
    "CVE-2024-42096",
    "CVE-2024-42119",
    "CVE-2024-42120",
    "CVE-2024-42124",
    "CVE-2024-42145",
    "CVE-2024-42223",
    "CVE-2024-42224"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2940-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2024:2940-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2024:2940-1 advisory.

    The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-39494: ima: Fix use-after-free on a dentry's dname.name (bsc#1227716).
    - CVE-2024-42096: x86: stop playing stack games in profile_pc() (bsc#1228633).
    - CVE-2024-39506: liquidio: adjust a NULL pointer handling path in lio_vf_rep_copy_packet (bsc#1227729).
    - CVE-2021-47619: i40e: Fix queues reservation for XDP (bsc#1226645).
    - CVE-2024-42145: IB/core: Implement a limit on UMAD receive List (bsc#1228743).
    - CVE-2024-42124: scsi: qedf: Make qedf_execute_tmf() non-preemptible (bsc#1228705).
    - CVE-2024-42223: media: dvb-frontends: tda10048: Fix integer overflow (bsc#1228726)
    - CVE-2024-42119: drm/amd/display: Skip finding free audio for unknown engine_id (bsc#1228584)
    - CVE-2024-42120: drm/amd/display: Check pipe offset before setting vblank (bsc#1228588)
    - CVE-2024-41095: drm/nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes (bsc#1228662)
    - CVE-2024-42224: net: dsa: mv88e6xxx: Correct check for empty list (bsc#1228723).
    - CVE-2024-41072: wifi: cfg80211: wext: add extra SIOCSIWSCAN data check (bsc#1228626).
    - CVE-2024-41048: skmsg: Skip zero length skb in sk_msg_recvmsg (bsc#1228565).
    - CVE-2024-40995: net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc() (bsc#1227830).
    - CVE-2024-41044: ppp: reject claimed-as-LCP but actually malformed packets (bsc#1228530).
    - CVE-2024-41066: ibmvnic: add tx check to prevent skb leak (bsc#1228640).
    - CVE-2024-42093: net/dpaa2: Avoid explicit cpumask var allocation on stack (bsc#1228680).
    - CVE-2024-41089: drm/nouveau/dispnv04: fix null pointer dereference in (bsc#1228658)
    - CVE-2024-41060: drm/radeon: check bo_va->bo is non-NULL before using it (bsc#1228567)
    - CVE-2022-48829: NFSD: Fix NFSv3 SETATTR/CREATE's handling of large file sizes (bsc#1228055).
    - CVE-2022-48828: NFSD: Fix ia_size underflow (bsc#1228054).
    - CVE-2022-48827: NFSD: Fix the behavior of READ near OFFSET_MAX (bsc#1228037).
    - CVE-2024-41078: btrfs: qgroup: fix quota root leak after quota disable failure (bsc#1228655).
    - CVE-2024-41071: wifi: mac80211: Avoid address calculations via out of bounds array indexing
    (bsc#1228625).
    - CVE-2024-41064: powerpc/eeh: avoid possible crash when edev->pdev changes (bsc#1228599).
    - CVE-2024-35949: btrfs: make sure that WRITTEN is set on all metadata blocks (bsc#1224700).
    - CVE-2024-41081: ila: block BH in ila_output() (bsc#1228617).
    - CVE-2024-40978: scsi: qedi: Fix crash while reading debugfs attribute (bsc#1227929).
    - CVE-2022-48792: scsi: pm8001: Fix use-after-free for aborted SSP/STP sas_task (bsc#1228013).
    - CVE-2022-48823: scsi: qedf: Fix refcount issue when LOGO is received during TMF (bsc#1228045).
    - CVE-2024-40998: ext4: fix uninitialized ratelimit_state->lock access in __ext4_fill_super()
    (bsc#1227866).
    - CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228561).
    - CVE-2024-40987: drm/amdgpu: fix UBSAN warning in kv_dpm.c (bsc#1228235)
    - CVE-2022-48826: drm/vc4: Fix deadlock on DSI device attach error (bsc#1227975)
    - CVE-2024-27437: vfio/pci: Disable auto-enable of exclusive INTx IRQ (bsc#1222625).
    - CVE-2024-41015: ocfs2: add bounds checking to ocfs2_check_dir_entry() (bsc#1228409).
    - CVE-2024-41016: ocfs2: strict bound check before memcmp in ocfs2_xattr_find_entry() (bsc#1228410).
    - CVE-2024-41063: bluetooth: hci_core: cancel all works upon hci_unregister_dev() (bsc#1228580).
    - CVE-2024-42070: netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers
    (bsc#1228470).
    - CVE-2024-41070: KVM: PPC: Book3S HV: Prevent UAF in kvm_spapr_tce_attach_iommu_group() (bsc#1228581).
    - CVE-2021-47405: HID: usbhid: free raw_report buffers in usbhid_stop (bsc#1225238).
    - CVE-2024-40988: drm/radeon: fix UBSAN warning in kv_dpm.c (bsc#1227957)
    - CVE-2024-40932: drm/exynos/vidi: fix memory leak in .get_modes() (bsc#1227828)
    - CVE-2021-47403: ipack: ipoctal: fix module reference leak (bsc#1225241).
    - CVE-2021-47388: mac80211: fix use-after-free in CCMP/GCMP RX (bsc#1225214).
    - CVE-2024-41014: xfs: add bounds checking to xlog_recover_process_data (bsc#1228408).
    - CVE-2024-41091: tun: add missing verification for short frame (bsc#1228327).
    - CVE-2024-41090: tap: add missing verification for short frame (bsc#1228328).
    - CVE-2024-40999: net: ena: Add validation for completion descriptors consistency (bsc#1227913).
    - CVE-2024-35837: net: mvpp2: clear BM pool before initialization (bsc#1224500).
    - CVE-2021-47588: sit: do not call ipip6_dev_free() from sit_init_net() (bsc#1226568).
    - CVE-2022-48804: vt_ioctl: fix array_index_nospec in vt_setactivate (bsc#1227968).
    - CVE-2024-40967: serial: imx: Introduce timeout when waiting on transmitter empty (bsc#1227891).
    - CVE-2024-40966: kABI: tty: add the option to have a tty reject a new ldisc (bsc#1227886).
    - CVE-2022-48850: net-sysfs: add check for netdevice being present to speed_show (bsc#1228071).
    - CVE-2021-47582: usb: core: Do not hold the device lock while sleeping in do_proc_control()
    (bsc#1226559).
    - CVE-2024-40982: ssb: fix potential NULL pointer dereference in ssb_device_uevent() (bsc#1227865).
    - CVE-2021-47468: isdn: mISDN: Fix sleeping function called from invalid context (bsc#1225346).
    - CVE-2021-47395: mac80211: limit injected vht mcs/nss in ieee80211_parse_tx_radiotap (bsc#1225326).
    - CVE-2022-48810: ipmr,ip6mr: acquire RTNL before calling ip[6]mr_free_table() on failure path
    (bsc#1227936).
    - CVE-2023-52594: Fixed potential array-index-out-of-bounds read in ath9k_htc_txstatus() (bsc#1221045).
    - CVE-2022-48855: sctp: fix kernel-infoleak for SCTP sockets (bsc#1228003).
    - CVE-2021-47580: scsi: scsi_debug: Fix type in min_t to avoid stack OOB (bsc#1226550).
    - CVE-2024-26735: ipv6: sr: fix possible use-after-free and null-ptr-deref (bsc#1222372).
    - CVE-2024-38560: scsi: bfa: Ensure the copied buf is NUL terminated (bsc#1226786).
    - CVE-2022-48811: ibmvnic: do not release napi in __ibmvnic_open() (bsc#1227928).
    - CVE-2021-0129: Improper access control in BlueZ may have allowed an authenticated user to potentially
    enable information disclosure via adjacent access (bsc#1186463).
    - CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure pairing that could permit a nearby
    man-in-the-middle attacker to identify the Passkey used during pairing (bsc#1179610).
    - CVE-2024-40937: gve: Clear napi->skb before dev_kfree_skb_any() (bsc#1227836).
    - CVE-2024-39507: net: hns3: fix kernel crash problem in concurrent scenario (bsc#1227730).
    - CVE-2024-40923: vmxnet3: disable rx data ring on dma allocation failure (bsc#1227786).
    - CVE-2024-40941: wifi: iwlwifi: mvm: do not read past the mfuart notifcation (bsc#1227771).
    - CVE-2022-48860: ethernet: Fix error handling in xemaclite_of_probe (bsc#1228008)
    - CVE-2022-48863: mISDN: Fix memory leak in dsp_pipeline_build() (bsc#1228063).
    - CVE-2024-40953: KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin() (bsc#1227806).
    - CVE-2024-39499: vmci: prevent speculation leaks by sanitizing event in event_deliver() (bsc#1227725)
    - CVE-2024-39509: HID: core: remove unnecessary WARN_ON() in implement() (bsc#1227733)
    - CVE-2024-39487: bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (bsc#1227573)
    - CVE-2024-35934: net/smc: reduce rtnl pressure in smc_pnet_create_pnetids_list() (bsc#1224641)
    - CVE-2024-40959: xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr() (bsc#1227884).
    - CVE-2024-35893: net/sched: act_skbmod: prevent kernel-infoleak (bsc#1224512)
    - CVE-2021-47441: mlxsw: thermal: Fix out-of-bounds memory accesses (bsc#1225224)
    - CVE-2021-47194: cfg80211: call cfg80211_stop_ap when switch from P2P_GO type (bsc#1222829)
    - CVE-2024-27020: netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (bsc#1223815)
    - CVE-2022-48775: Drivers: hv: vmbus: Fix memory leak in vmbus_add_channel_kobj (bsc#1227924).
    - CVE-2024-27019: netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (bsc#1223813)
    - CVE-2024-40929: wifi: iwlwifi: mvm: check n_ssids before accessing the ssids (bsc#1227774).
    - CVE-2024-40912: wifi: mac80211: Fix deadlock in ieee80211_sta_ps_deliver_wakeup() (bsc#1227790).
    - CVE-2024-40942: wifi: mac80211: mesh: Fix leak of mesh_preq_queue objects (bsc#1227770).
    - CVE-2022-48857: NFC: port100: fix use-after-free in port100_send_complete (bsc#1228005).
    - CVE-2024-36902: ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action() (bsc#1225719).
    - CVE-2021-47606: net: netlink: af_netlink: Prevent empty skb by adding a check on len. (bsc#1226555).
    - CVE-2024-40901: scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (bsc#1227762).
    - CVE-2024-26924: scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (bsc#1225820).
    - CVE-2024-26830: Fixed i40e to not allow untrusted VF to remove administratively set MAC (bsc#1223012).
    - CVE-2021-47516: nfp: Fix memory leak in nfp_cpp_area_cache_add() (bsc#1225427).
    - CVE-2021-47501: i40e: Fix NULL pointer dereference in i40e_dbg_dump_desc (bsc#1225361).
    - CVE-2024-39501: drivers: core: synchronize really_probe() and dev_uevent() (bsc#1227754).
    - CVE-2023-52743: ice: Do not use WQ_MEM_RECLAIM flag for workqueue (bsc#1225003)
    - CVE-2021-47542: net: qlogic: qlcnic: Fix a NULL pointer dereference in qlcnic_83xx_add_rings()
    (bsc#1225455)
    - CVE-2024-36901: ipv6: prevent NULL dereference in ip6_output() (bsc#1225711)
    - CVE-2024-36004: i40e: Do not use WQ_MEM_RECLAIM flag for workqueue (bsc#1224545)
    - CVE-2024-27025: nbd: null check for nla_nest_start (bsc#1223778)
    - CVE-2021-47599: btrfs: use latest_dev in btrfs_show_devname (bsc#1226571).
    - CVE-2023-52435: net: prevent mss overflow in skb_segment() (bsc#1220138).
    - CVE-2024-26663: tipc: Check the bearer type before calling tipc_udp_nl_bearer_add() (bsc#1222326).
    - CVE-2021-47597: inet_diag: fix kernel-infoleak for UDP sockets (bsc#1226553).
    - CVE-2024-39490: ipv6: sr: fix missing sk_buff release in seg6_input_core (bsc#1227626).
    - CVE-2024-38558: net: openvswitch: fix overwriting ct original tuple for ICMPv6 (bsc#1226783).
    - CVE-2024-26615: net/smc: fix illegal rmb_desc access in SMC-D connection dump (bsc#1220942).
    - CVE-2023-52619: Fixed possible crash when setting number of cpus to an odd number in pstore/ram
    (bsc#1221618).
    - CVE-2024-26659: Fixed wrong handling of isoc Babble and Buffer Overrun events in xhci (bsc#1222317).
    - CVE-2024-35978: Bluetooth: Fix memory leak in hci_req_sync_complete() (bsc#1224571).
    - CVE-2023-52669: crypto: s390/aes - Fix buffer overread in CTR mode (bsc#1224637).
    - CVE-2023-52615: Fixed page fault dead lock on mmap-ed hwrng (bsc#1221614).
    - CVE-2023-52612: Fixed req->dst buffer overflow in crypto/scomp (bsc#1221616).
    - CVE-2024-35995: ACPI: CPPC: Use access_width over bit_width for system memory accesses (bsc#1224557).
    - CVE-2023-52623: Fixed suspicious RCU usage in SUNRPC (bsc#1222060).
    - CVE-2021-47295: net: sched: fix memory leak in tcindex_partial_destroy_work (bsc#1224975)
    - CVE-2024-38630: watchdog: cpu5wdt.c: Fix use-after-free bug caused by cpu5wdt_trigger (bsc#1226908).
    - CVE-2021-47559: net/smc: Fix NULL pointer dereferencing in smc_vlan_by_tcpsk() (bsc#1225396).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1088701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228850");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036478.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47219");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47403");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47438");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38560");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39499");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42223");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42224");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26558");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-42093");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_225-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLED12|SLED_SAP12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-4.12.14-122.225.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.225.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.225.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.225.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.225.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.225.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.225.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.225.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.225.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.225.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.225.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'kernel-default-kgraft-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_225-default-1-8.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.225.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.225.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.225.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.225.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
