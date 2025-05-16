#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0564-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216456);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-2024-40980",
    "CVE-2024-46858",
    "CVE-2024-49948",
    "CVE-2024-49978",
    "CVE-2024-50142",
    "CVE-2024-50251",
    "CVE-2024-50258",
    "CVE-2024-50304",
    "CVE-2024-53123",
    "CVE-2024-53187",
    "CVE-2024-53203",
    "CVE-2024-56592",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56608",
    "CVE-2024-56610",
    "CVE-2024-56633",
    "CVE-2024-56650",
    "CVE-2024-56658",
    "CVE-2024-56665",
    "CVE-2024-56679",
    "CVE-2024-56693",
    "CVE-2024-56707",
    "CVE-2024-56715",
    "CVE-2024-56725",
    "CVE-2024-56726",
    "CVE-2024-56727",
    "CVE-2024-56728",
    "CVE-2024-56763",
    "CVE-2024-57802",
    "CVE-2024-57882",
    "CVE-2024-57884",
    "CVE-2024-57917",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57946",
    "CVE-2025-21652",
    "CVE-2025-21653",
    "CVE-2025-21655",
    "CVE-2025-21663",
    "CVE-2025-21664",
    "CVE-2025-21665",
    "CVE-2025-21666",
    "CVE-2025-21667",
    "CVE-2025-21668",
    "CVE-2025-21669",
    "CVE-2025-21670",
    "CVE-2025-21673",
    "CVE-2025-21674",
    "CVE-2025-21675",
    "CVE-2025-21676",
    "CVE-2025-21678",
    "CVE-2025-21681",
    "CVE-2025-21682"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0564-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2025:0564-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:0564-1 advisory.

    The SUSE Linux Enterprise 15 SP6 Confidential Computing kernel was updated to receive various security
    bugfixes.


    The following security bugs were fixed:

    - CVE-2024-40980: drop_monitor: replace spin_lock by raw_spin_lock (bsc#1227937).
    - CVE-2024-46858: mptcp: pm: Fix uaf in __timer_delete_sync (bsc#1231088).
    - CVE-2024-49948: net: add more sanity checks to qdisc_pkt_len_init() (bsc#1232161).
    - CVE-2024-49978: gso: fix udp gso fraglist segmentation after pull from frag_list (bsc#1232101).
    - CVE-2024-50142: xfrm: validate new SA's prefixlen using SA family when sel.family is unset
    (bsc#1233028).
    - CVE-2024-50251: netfilter: nft_payload: sanitize offset and length before calling skb_checksum()
    (bsc#1233248).
    - CVE-2024-50258: net: fix crash when config small gso_max_size/gso_ipv4_max_size (bsc#1233221).
    - CVE-2024-50304: ipv4: ip_tunnel: Fix suspicious RCU usage warning in ip_tunnel_find() (bsc#1233522).
    - CVE-2024-53123: mptcp: error out earlier on disconnect (bsc#1234070).
    - CVE-2024-53187: io_uring: check for overflows in io_pin_pages (bsc#1234947).
    - CVE-2024-53203: usb: typec: fix potential array underflow in ucsi_ccg_sync_control() (bsc#1235001).
    - CVE-2024-56592: bpf: Call free_htab_elem() after htab_unlock_bucket() (bsc#1235244).
    - CVE-2024-56600: net: inet6: do not leave a dangling sk pointer in inet6_create() (bsc#1235217).
    - CVE-2024-56601: net: inet: do not leave a dangling sk pointer in inet_create() (bsc#1235230).
    - CVE-2024-56608: drm/amd/display: Fix out-of-bounds access in 'dcn21_link_encoder_create' (bsc#1235487).
    - CVE-2024-56610: kcsan: Turn report_filterlist_lock into a raw_spinlock (bsc#1235390).
    - CVE-2024-56633: tcp_bpf: Fix the sk_mem_uncharge logic in tcp_bpf_sendmsg (bsc#1235485).
    - CVE-2024-56650: netfilter: x_tables: fix LED ID check in led_tg_check() (bsc#1235430).
    - CVE-2024-56658: net: defer final 'struct net' free in netns dismantle (bsc#1235441).
    - CVE-2024-56665: bpf,perf: Fix invalid prog_array access in perf_event_detach_bpf_prog (bsc#1235489).
    - CVE-2024-56679: octeontx2-pf: handle otx2_mbox_get_rsp errors in otx2_common.c (bsc#1235498).
    - CVE-2024-56693: brd: defer automatic disk creation until module initialization succeeds (bsc#1235418).
    - CVE-2024-56707: octeontx2-pf: handle otx2_mbox_get_rsp errors in otx2_dmac_flt.c (bsc#1235545).
    - CVE-2024-56715: ionic: Fix netdev notifier unregister on failure (bsc#1235612).
    - CVE-2024-56725: octeontx2-pf: handle otx2_mbox_get_rsp errors in otx2_dcbnl.c (bsc#1235578).
    - CVE-2024-56726: octeontx2-pf: handle otx2_mbox_get_rsp errors in cn10k.c (bsc#1235582).
    - CVE-2024-56727: octeontx2-pf: handle otx2_mbox_get_rsp errors in otx2_flows.c (bsc#1235583).
    - CVE-2024-56728: octeontx2-pf: handle otx2_mbox_get_rsp errors in otx2_ethtool.c (bsc#1235656).
    - CVE-2024-56763: tracing: Prevent bad count for tracing_cpumask_write (bsc#1235638).
    - CVE-2024-57802: netrom: check buffer length before accessing it (bsc#1235941).
    - CVE-2024-57882: mptcp: fix TCP options overflow. (bsc#1235914).
    - CVE-2024-57884: mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim()
    (bsc#1235948).
    - CVE-2024-57917: topology: Keep the cpumask unchanged when printing cpumap (bsc#1236127).
    - CVE-2024-57931: selinux: ignore unknown extended permissions (bsc#1236192).
    - CVE-2024-57938: net/sctp: Prevent autoclose integer overflow in sctp_association_init() (bsc#1236182).
    - CVE-2024-57946: virtio-blk: do not keep queue frozen during system suspend (bsc#1236247).
    - CVE-2025-21652: ipvlan: Fix use-after-free in ipvlan_get_iflink() (bsc#1236160).
    - CVE-2025-21653: net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute (bsc#1236161).
    - CVE-2025-21655: io_uring/eventfd: ensure io_eventfd_signal() defers another RCU period (bsc#1236163).
    - CVE-2025-21663: net: stmmac: dwmac-tegra: Read iommu stream id from device tree (bsc#1236260).
    - CVE-2025-21664: dm thin: make get_first_thin use rcu-safe list first function (bsc#1236262).
    - CVE-2025-21665: filemap: avoid truncating 64-bit offset to 32 bits (bsc#1236684).
    - CVE-2025-21666: vsock: prevent null-ptr-deref in vsock_*[has_data|has_space] (bsc#1236680).
    - CVE-2025-21667: iomap: avoid avoid truncating 64-bit offset to 32 bits (bsc#1236681).
    - CVE-2025-21668: pmdomain: imx8mp-blk-ctrl: add missing loop break condition (bsc#1236682).
    - CVE-2025-21669: vsock/virtio: discard packets if the transport changes (bsc#1236683).
    - CVE-2025-21670: vsock/bpf: return early if transport is not assigned (bsc#1236685).
    - CVE-2025-21673: smb: client: fix double free of TCP_Server_Info::hostname (bsc#1236689).
    - CVE-2025-21674: net/mlx5e: Fix inversion dependency warning while enabling IPsec tunnel (bsc#1236688).
    - CVE-2025-21675: net/mlx5: Clear port select structure when fail to create (bsc#1236694).
    - CVE-2025-21676: net: fec: handle page_pool_dev_alloc_pages error (bsc#1236696).
    - CVE-2025-21678: gtp: Destroy device along with udp socket's netns dismantle (bsc#1236698).
    - CVE-2025-21681: openvswitch: fix lockup on tx to unregistering netdev with carrier (bsc#1236702).
    - CVE-2025-21682: eth: bnxt: always recalculate features after XDP clearing, fix null-deref (bsc#1236703).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236761");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020361.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc1a97c4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50251");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50258");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21682");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21652");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-coco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-coco-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-coco_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-coco_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-coco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-coco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-coco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-coco");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-coco-6.4.0-15061.15.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-coco-devel-6.4.0-15061.15.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-coco_debug-6.4.0-15061.15.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-coco_debug-devel-6.4.0-15061.15.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-devel-coco-6.4.0-15061.15.coco15sp6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-source-coco-6.4.0-15061.15.coco15sp6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-syms-coco-6.4.0-15061.15.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'reiserfs-kmp-coco-6.4.0-15061.15.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-coco / kernel-coco-devel / kernel-coco_debug / etc');
}
