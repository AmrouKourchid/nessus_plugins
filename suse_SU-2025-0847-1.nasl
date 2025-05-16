#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0847-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(232678);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2023-52924",
    "CVE-2023-52925",
    "CVE-2024-26708",
    "CVE-2024-26810",
    "CVE-2024-40980",
    "CVE-2024-41055",
    "CVE-2024-44974",
    "CVE-2024-45009",
    "CVE-2024-45010",
    "CVE-2024-46858",
    "CVE-2024-47701",
    "CVE-2024-49884",
    "CVE-2024-49950",
    "CVE-2024-50029",
    "CVE-2024-50036",
    "CVE-2024-50073",
    "CVE-2024-50085",
    "CVE-2024-50115",
    "CVE-2024-50142",
    "CVE-2024-50185",
    "CVE-2024-50294",
    "CVE-2024-53123",
    "CVE-2024-53147",
    "CVE-2024-53173",
    "CVE-2024-53176",
    "CVE-2024-53177",
    "CVE-2024-53178",
    "CVE-2024-53226",
    "CVE-2024-53239",
    "CVE-2024-56539",
    "CVE-2024-56548",
    "CVE-2024-56568",
    "CVE-2024-56579",
    "CVE-2024-56592",
    "CVE-2024-56605",
    "CVE-2024-56633",
    "CVE-2024-56647",
    "CVE-2024-56658",
    "CVE-2024-56720",
    "CVE-2024-57882",
    "CVE-2024-57889",
    "CVE-2024-57948",
    "CVE-2024-57979",
    "CVE-2024-57994",
    "CVE-2025-21636",
    "CVE-2025-21637",
    "CVE-2025-21638",
    "CVE-2025-21639",
    "CVE-2025-21640",
    "CVE-2025-21647",
    "CVE-2025-21665",
    "CVE-2025-21666",
    "CVE-2025-21667",
    "CVE-2025-21668",
    "CVE-2025-21669",
    "CVE-2025-21670",
    "CVE-2025-21673",
    "CVE-2025-21675",
    "CVE-2025-21680",
    "CVE-2025-21681",
    "CVE-2025-21684",
    "CVE-2025-21687",
    "CVE-2025-21688",
    "CVE-2025-21689",
    "CVE-2025-21690",
    "CVE-2025-21692",
    "CVE-2025-21697",
    "CVE-2025-21699",
    "CVE-2025-21700",
    "CVE-2025-21705",
    "CVE-2025-21715",
    "CVE-2025-21716",
    "CVE-2025-21719",
    "CVE-2025-21724",
    "CVE-2025-21725",
    "CVE-2025-21728",
    "CVE-2025-21733",
    "CVE-2025-21754",
    "CVE-2025-21767",
    "CVE-2025-21790",
    "CVE-2025-21795",
    "CVE-2025-21799",
    "CVE-2025-21802"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0847-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2025:0847-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2025:0847-1 advisory.

    The SUSE Linux Enterprise 15 SP6 Azure kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-26708: mptcp: fix inconsistent state on fastopen race (bsc#1222672).
    - CVE-2024-40980: drop_monitor: replace spin_lock by raw_spin_lock (bsc#1227937).
    - CVE-2024-44974: mptcp: pm: avoid possible UaF when selecting endp (bsc#1230235).
    - CVE-2024-45009: mptcp: pm: only decrement add_addr_accepted for MPJ req (bsc#1230438).
    - CVE-2024-45010: mptcp: pm: only mark 'subflow' endp as available (bsc#1230439).
    - CVE-2024-46858: mptcp: pm: Fix uaf in __timer_delete_sync (bsc#1231088).
    - CVE-2024-50029: Bluetooth: hci_conn: Fix UAF in hci_enhanced_setup_sync (bsc#1231949).
    - CVE-2024-50036: net: do not delay dst_entries_add() in dst_release() (bsc#1231912).
    - CVE-2024-50085: mptcp: pm: fix UaF read in mptcp_pm_nl_rm_addr_or_subflow (bsc#1232508).
    - CVE-2024-50142: xfrm: validate new SA's prefixlen using SA family when sel.family is unset
    (bsc#1233028).
    - CVE-2024-50185: kABI fix for mptcp: handle consistently DSS corruption (bsc#1233109).
    - CVE-2024-50294: rxrpc: Fix missing locking causing hanging calls (bsc#1233483).
    - CVE-2024-53123: mptcp: error out earlier on disconnect (bsc#1234070).
    - CVE-2024-53147: exfat: fix out-of-bounds access of directory entries (bsc#1234857).
    - CVE-2024-53176: smb: During unmount, ensure all cached dir instances drop their dentry (bsc#1234894).
    - CVE-2024-53177: smb: prevent use-after-free due to open_cached_dir error paths (bsc#1234896).
    - CVE-2024-53178: smb: Do not leak cfid when reconnect races with open_cached_dir (bsc#1234895).
    - CVE-2024-56568: iommu/arm-smmu: Defer probe of clients after smmu device bound (bsc#1235032).
    - CVE-2024-56592: bpf: Call free_htab_elem() after htab_unlock_bucket() (bsc#1235244).
    - CVE-2024-56633: selftests/bpf: Add apply_bytes test to test_txmsg_redir_wait_sndmem in test_sockmap
    (bsc#1235485).
    - CVE-2024-56647: net: Fix icmp host relookup triggering ip_rt_bug (bsc#1235435).
    - CVE-2024-56658: net: defer final 'struct net' free in netns dismantle (bsc#1235441).
    - CVE-2024-56720: bpf, sockmap: Several fixes to bpf_msg_pop_data (bsc#1235592).
    - CVE-2024-57882: mptcp: fix TCP options overflow. (bsc#1235914).
    - CVE-2024-57994: ptr_ring: do not block hard interrupts in ptr_ring_resize_multiple() (bsc#1237901).
    - CVE-2025-21636: sctp: sysctl: plpmtud_probe_interval: avoid using current->nsproxy (bsc#1236113).
    - CVE-2025-21637: sctp: sysctl: udp_port: avoid using current->nsproxy (bsc#1236114).
    - CVE-2025-21638: sctp: sysctl: auth_enable: avoid using current->nsproxy (bsc#1236115).
    - CVE-2025-21639: sctp: sysctl: rto_min/max: avoid using current->nsproxy (bsc#1236122).
    - CVE-2025-21640: sctp: sysctl: cookie_hmac_alg: avoid using current->nsproxy (bsc#1236123).
    - CVE-2025-21647: sched: sch_cake: add bounds checks to host bulk flow fairness counts (bsc#1236133).
    - CVE-2025-21665: filemap: avoid truncating 64-bit offset to 32 bits (bsc#1236684).
    - CVE-2025-21666: vsock: prevent null-ptr-deref in vsock_*[has_data|has_space] (bsc#1236680).
    - CVE-2025-21667: iomap: avoid avoid truncating 64-bit offset to 32 bits (bsc#1236681).
    - CVE-2025-21668: pmdomain: imx8mp-blk-ctrl: add missing loop break condition (bsc#1236682).
    - CVE-2025-21669: vsock/virtio: discard packets if the transport changes (bsc#1236683).
    - CVE-2025-21670: vsock/bpf: return early if transport is not assigned (bsc#1236685).
    - CVE-2025-21673: smb: client: fix double free of TCP_Server_Info::hostname (bsc#1236689).
    - CVE-2025-21675: net/mlx5: Clear port select structure when fail to create (bsc#1236694).
    - CVE-2025-21680: pktgen: Avoid out-of-bounds access in get_imix_entries (bsc#1236700).
    - CVE-2025-21681: openvswitch: fix lockup on tx to unregistering netdev with carrier (bsc#1236702).
    - CVE-2025-21687: vfio/platform: check the bounds of read/write syscalls (bsc#1237045).
    - CVE-2025-21692: net: sched: fix ets qdisc OOB Indexing (bsc#1237028).
    - CVE-2025-21700: net: sched: Disallow replacing of child qdisc from one parent to another (bsc#1237159).
    - CVE-2025-21728: bpf: Send signals asynchronously if !preemptible (bsc#1237879).
    - CVE-2024-57979: kABI workaround for pps changes (bsc#1238521).
    - CVE-2025-21705: mptcp: handle fastopen disconnect correctly (bsc#1238525).
    - CVE-2025-21715: net: davicom: fix UAF in dm9000_drv_remove (bsc#1237889).
    - CVE-2025-21716: vxlan: Fix uninit-value in vxlan_vnifilter_dump() (bsc#1237891).
    - CVE-2025-21719: ipmr: do not call mr_mfc_uses_dev() for unres entries (bsc#1238860).
    - CVE-2025-21724: iommufd/iova_bitmap: Fix shift-out-of-bounds in iova_bitmap_offset_to_index()
    (bsc#1238863).
    - CVE-2025-21725: smb: client: fix oops due to unset link speed (bsc#1238877).
    - CVE-2025-21733: tracing/osnoise: Fix resetting of tracepoints (bsc#1238494).
    - CVE-2025-21754: btrfs: fix assertion failure when splitting ordered extent after transaction abort
    (bsc#1238496).
    - CVE-2025-21767: clocksource: Use migrate_disable() to avoid calling get_random_u32() in atomic context
    (bsc#1238509).
    - CVE-2025-21790: vxlan: check vxlan_vnigroup_init() return value (bsc#1238753).
    - CVE-2025-21795: NFSD: fix hang in nfsd4_shutdown_callback (bsc#1238759).
    - CVE-2025-21799: net: ethernet: ti: am65-cpsw: fix freeing IRQ in am65_cpsw_nuss_remove_tx_chns()
    (bsc#1238739).
    - CVE-2025-21802: net: hns3: fix oops when unload drivers paralleling (bsc#1238751).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1012628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238877");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-March/020505.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9867d361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50294");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53178");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56568");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21716");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21802");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21692");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/13");

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

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.31.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.31.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.31.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.31.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.31.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'cluster-md-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-extra-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-extra-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-optional-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-optional-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-vdso-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.31.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.31.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-azure-6.4.0-150600.8.31.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
