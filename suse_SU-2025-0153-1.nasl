#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0153-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214356);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2024-8805",
    "CVE-2024-26924",
    "CVE-2024-27397",
    "CVE-2024-35839",
    "CVE-2024-36908",
    "CVE-2024-39480",
    "CVE-2024-41042",
    "CVE-2024-44934",
    "CVE-2024-44996",
    "CVE-2024-47678",
    "CVE-2024-49854",
    "CVE-2024-49884",
    "CVE-2024-49915",
    "CVE-2024-50016",
    "CVE-2024-50018",
    "CVE-2024-50039",
    "CVE-2024-50047",
    "CVE-2024-50143",
    "CVE-2024-50154",
    "CVE-2024-50202",
    "CVE-2024-50203",
    "CVE-2024-50211",
    "CVE-2024-50228",
    "CVE-2024-50256",
    "CVE-2024-50262",
    "CVE-2024-50272",
    "CVE-2024-50278",
    "CVE-2024-50280",
    "CVE-2024-53050",
    "CVE-2024-53064",
    "CVE-2024-53090",
    "CVE-2024-53099",
    "CVE-2024-53103",
    "CVE-2024-53105",
    "CVE-2024-53111",
    "CVE-2024-53113",
    "CVE-2024-53117",
    "CVE-2024-53118",
    "CVE-2024-53119",
    "CVE-2024-53120",
    "CVE-2024-53122",
    "CVE-2024-53125",
    "CVE-2024-53126",
    "CVE-2024-53127",
    "CVE-2024-53129",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53133",
    "CVE-2024-53134",
    "CVE-2024-53136",
    "CVE-2024-53141",
    "CVE-2024-53142",
    "CVE-2024-53144",
    "CVE-2024-53146",
    "CVE-2024-53148",
    "CVE-2024-53150",
    "CVE-2024-53151",
    "CVE-2024-53154",
    "CVE-2024-53155",
    "CVE-2024-53156",
    "CVE-2024-53157",
    "CVE-2024-53158",
    "CVE-2024-53159",
    "CVE-2024-53160",
    "CVE-2024-53161",
    "CVE-2024-53162",
    "CVE-2024-53166",
    "CVE-2024-53169",
    "CVE-2024-53171",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53179",
    "CVE-2024-53180",
    "CVE-2024-53188",
    "CVE-2024-53190",
    "CVE-2024-53191",
    "CVE-2024-53200",
    "CVE-2024-53201",
    "CVE-2024-53202",
    "CVE-2024-53206",
    "CVE-2024-53207",
    "CVE-2024-53208",
    "CVE-2024-53209",
    "CVE-2024-53210",
    "CVE-2024-53213",
    "CVE-2024-53214",
    "CVE-2024-53215",
    "CVE-2024-53216",
    "CVE-2024-53217",
    "CVE-2024-53222",
    "CVE-2024-53224",
    "CVE-2024-53229",
    "CVE-2024-53234",
    "CVE-2024-53237",
    "CVE-2024-53240",
    "CVE-2024-53241",
    "CVE-2024-56536",
    "CVE-2024-56539",
    "CVE-2024-56549",
    "CVE-2024-56551",
    "CVE-2024-56562",
    "CVE-2024-56566",
    "CVE-2024-56567",
    "CVE-2024-56576",
    "CVE-2024-56582",
    "CVE-2024-56599",
    "CVE-2024-56604",
    "CVE-2024-56605",
    "CVE-2024-56645",
    "CVE-2024-56667",
    "CVE-2024-56752",
    "CVE-2024-56754",
    "CVE-2024-56755",
    "CVE-2024-56756"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0153-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2025:0153-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0153-1 advisory.

    The SUSE Linux Enterprise 15 SP6 RT kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-26924: scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (bsc#1225820).
    - CVE-2024-27397: netfilter: nf_tables: use timestamp to check for set element timeout (bsc#1224095).
    - CVE-2024-35839: kABI fix for netfilter: bridge: replace physindev with physinif in nf_bridge_info
    (bsc#1224726).
    - CVE-2024-41042: Prefer nft_chain_validate (bsc#1228526).
    - CVE-2024-44934: net: bridge: mcast: wait for previous gc cycles when removing port (bsc#1229809).
    - CVE-2024-44996: vsock: fix recursive ->recvmsg calls (bsc#1230205).
    - CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).
    - CVE-2024-50018: net: napi: Prevent overflow of napi_defer_hard_irqs (bsc#1232419).
    - CVE-2024-50039: kABI: Restore deleted EXPORT_SYMBOL(__qdisc_calculate_pkt_len) (bsc#1231909).
    - CVE-2024-50143: udf: fix uninit-value use in udf_get_fileshortad (bsc#1233038).
    - CVE-2024-50202: nilfs2: propagate directory read errors from nilfs_find_entry() (bsc#1233324).
    - CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6() (bsc#1233200).
    - CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key() (bsc#1233239).
    - CVE-2024-50278, CVE-2024-50280: dm cache: fix flushing uninitialized delayed_work on cache_ctr error
    (bsc#1233467 bsc#1233469).
    - CVE-2024-50278: dm cache: fix potential out-of-bounds access on the first resume (bsc#1233467).
    - CVE-2024-53050: drm/i915/hdcp: Add encoder check in hdcp2_get_capability (bsc#1233546).
    - CVE-2024-53064: idpf: fix idpf_vc_core_init error path (bsc#1233558 bsc#1234464).
    - CVE-2024-53090: afs: Fix lock recursion (bsc#1233637).
    - CVE-2024-53099: bpf: Check validity of link->type in bpf_link_show_fdinfo() (bsc#1233772).
    - CVE-2024-53105: mm: page_alloc: move mlocked flag clearance into free_pages_prepare() (bsc#1234069).
    - CVE-2024-53111: mm/mremap: fix address wraparound in move_page_tables() (bsc#1234086).
    - CVE-2024-53113: mm: fix NULL pointer dereference in alloc_pages_bulk_noprof (bsc#1234077).
    - CVE-2024-53117: virtio/vsock: Improve MSG_ZEROCOPY error handling (bsc#1234079).
    - CVE-2024-53118: vsock: Fix sk_error_queue memory leak (bsc#1234071).
    - CVE-2024-53119: virtio/vsock: Fix accept_queue memory leak (bsc#1234073).
    - CVE-2024-53122: mptcp: cope racing subflow creation in mptcp_rcv_space_adjust (bsc#1234076).
    - CVE-2024-53125: bpf: sync_linked_regs() must preserve subreg_def (bsc#1234156).
    - CVE-2024-53130: nilfs2: fix null-ptr-deref in block_dirty_buffer tracepoint (bsc#1234219).
    - CVE-2024-53131: nilfs2: fix null-ptr-deref in block_touch_buffer tracepoint (bsc#1234220).
    - CVE-2024-53133: drm/amd/display: Handle dml allocation failure to avoid crash (bsc#1234221)
    - CVE-2024-53134: pmdomain: imx93-blk-ctrl: correct remove path (bsc#1234159).
    - CVE-2024-53141: netfilter: ipset: add missing range check in bitmap_ip_uadt (bsc#1234381).
    - CVE-2024-53160: rcu/kvfree: Fix data-race in __mod_timer / kvfree_call_rcu (bsc#1234810).
    - CVE-2024-53161: EDAC/bluefield: Fix potential integer overflow (bsc#1234856).
    - CVE-2024-53179: smb: client: fix use-after-free of signing key (bsc#1234921).
    - CVE-2024-53214: vfio/pci: Properly hide first-in-list PCIe extended capability (bsc#1235004).
    - CVE-2024-53216: nfsd: fix UAF when access ex_uuid or ex_stats (bsc#1235003).
    - CVE-2024-53222: zram: fix NULL pointer in comp_algorithm_show() (bsc#1234974).
    - CVE-2024-53234: erofs: handle NONHEAD !delta[1] lclusters gracefully (bsc#1235045).
    - CVE-2024-53240: xen/netfront: fix crash when removing device (bsc#1234281).
    - CVE-2024-53241: x86/xen: use new hypercall functions instead of hypercall page (XSA-466 bsc#1234282).
    - CVE-2024-56549: cachefiles: Fix NULL pointer dereference in object->file (bsc#1234912).
    - CVE-2024-56566: mm/slub: Avoid list corruption when removing a slab from the full list (bsc#1235033).
    - CVE-2024-56582: btrfs: fix use-after-free in btrfs_encoded_read_endio() (bsc#1235128).
    - CVE-2024-56599: wifi: ath10k: avoid NULL pointer error during sdio remove (bsc#1235138).
    - CVE-2024-56604: Bluetooth: RFCOMM: avoid leaving dangling sk pointer in rfcomm_sock_alloc()
    (bsc#1235056).
    - CVE-2024-56755: netfs/fscache: Add a memory barrier for FSCACHE_VOLUME_CREATING (bsc#1234920).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235550");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020150.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9587c699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50256");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50272");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50278");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53050");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53111");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53122");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53136");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53169");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53174");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53190");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53209");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53213");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53215");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8805");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-6_4_0-150600_10_23-rt");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-rt-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-rt-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-devel-rt-6.4.0-150600.10.23.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt-devel-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt-extra-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt-livepatch-devel-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt-optional-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt-vdso-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt_debug-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt_debug-devel-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-rt_debug-vdso-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-rt-6.4.0-150600.10.23.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-rt-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-rt-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-rt-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-rt-6.4.0-150600.10.23.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-livepatch-6_4_0-150600_10_23-rt-1-150600.1.3.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
