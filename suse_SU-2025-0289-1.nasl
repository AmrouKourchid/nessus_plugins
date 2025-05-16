#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0289-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214901);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2023-52489",
    "CVE-2023-52923",
    "CVE-2024-5660",
    "CVE-2024-8805",
    "CVE-2024-26596",
    "CVE-2024-26924",
    "CVE-2024-27397",
    "CVE-2024-35839",
    "CVE-2024-36476",
    "CVE-2024-36908",
    "CVE-2024-36915",
    "CVE-2024-39282",
    "CVE-2024-39480",
    "CVE-2024-41042",
    "CVE-2024-43913",
    "CVE-2024-44934",
    "CVE-2024-44996",
    "CVE-2024-45828",
    "CVE-2024-46680",
    "CVE-2024-46765",
    "CVE-2024-46800",
    "CVE-2024-46896",
    "CVE-2024-47141",
    "CVE-2024-47143",
    "CVE-2024-47678",
    "CVE-2024-47809",
    "CVE-2024-48873",
    "CVE-2024-48881",
    "CVE-2024-49569",
    "CVE-2024-49854",
    "CVE-2024-49884",
    "CVE-2024-49915",
    "CVE-2024-49944",
    "CVE-2024-49951",
    "CVE-2024-49952",
    "CVE-2024-49998",
    "CVE-2024-50016",
    "CVE-2024-50018",
    "CVE-2024-50039",
    "CVE-2024-50047",
    "CVE-2024-50051",
    "CVE-2024-50106",
    "CVE-2024-50143",
    "CVE-2024-50151",
    "CVE-2024-50154",
    "CVE-2024-50199",
    "CVE-2024-50202",
    "CVE-2024-50203",
    "CVE-2024-50211",
    "CVE-2024-50228",
    "CVE-2024-50252",
    "CVE-2024-50256",
    "CVE-2024-50262",
    "CVE-2024-50272",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50280",
    "CVE-2024-50296",
    "CVE-2024-50299",
    "CVE-2024-52332",
    "CVE-2024-53043",
    "CVE-2024-53050",
    "CVE-2024-53051",
    "CVE-2024-53055",
    "CVE-2024-53056",
    "CVE-2024-53064",
    "CVE-2024-53090",
    "CVE-2024-53091",
    "CVE-2024-53095",
    "CVE-2024-53099",
    "CVE-2024-53103",
    "CVE-2024-53105",
    "CVE-2024-53110",
    "CVE-2024-53111",
    "CVE-2024-53113",
    "CVE-2024-53117",
    "CVE-2024-53118",
    "CVE-2024-53119",
    "CVE-2024-53120",
    "CVE-2024-53121",
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
    "CVE-2024-53138",
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
    "CVE-2024-53164",
    "CVE-2024-53166",
    "CVE-2024-53168",
    "CVE-2024-53169",
    "CVE-2024-53170",
    "CVE-2024-53171",
    "CVE-2024-53172",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53175",
    "CVE-2024-53179",
    "CVE-2024-53180",
    "CVE-2024-53185",
    "CVE-2024-53188",
    "CVE-2024-53190",
    "CVE-2024-53191",
    "CVE-2024-53194",
    "CVE-2024-53195",
    "CVE-2024-53196",
    "CVE-2024-53197",
    "CVE-2024-53198",
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
    "CVE-2024-53227",
    "CVE-2024-53229",
    "CVE-2024-53230",
    "CVE-2024-53231",
    "CVE-2024-53232",
    "CVE-2024-53233",
    "CVE-2024-53234",
    "CVE-2024-53236",
    "CVE-2024-53237",
    "CVE-2024-53239",
    "CVE-2024-53240",
    "CVE-2024-53241",
    "CVE-2024-53685",
    "CVE-2024-53690",
    "CVE-2024-54680",
    "CVE-2024-55639",
    "CVE-2024-55881",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56372",
    "CVE-2024-56531",
    "CVE-2024-56532",
    "CVE-2024-56533",
    "CVE-2024-56536",
    "CVE-2024-56538",
    "CVE-2024-56539",
    "CVE-2024-56543",
    "CVE-2024-56546",
    "CVE-2024-56548",
    "CVE-2024-56549",
    "CVE-2024-56551",
    "CVE-2024-56557",
    "CVE-2024-56558",
    "CVE-2024-56562",
    "CVE-2024-56566",
    "CVE-2024-56567",
    "CVE-2024-56568",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56571",
    "CVE-2024-56572",
    "CVE-2024-56573",
    "CVE-2024-56574",
    "CVE-2024-56575",
    "CVE-2024-56576",
    "CVE-2024-56577",
    "CVE-2024-56578",
    "CVE-2024-56582",
    "CVE-2024-56584",
    "CVE-2024-56587",
    "CVE-2024-56588",
    "CVE-2024-56589",
    "CVE-2024-56590",
    "CVE-2024-56593",
    "CVE-2024-56594",
    "CVE-2024-56595",
    "CVE-2024-56596",
    "CVE-2024-56597",
    "CVE-2024-56598",
    "CVE-2024-56599",
    "CVE-2024-56602",
    "CVE-2024-56603",
    "CVE-2024-56604",
    "CVE-2024-56605",
    "CVE-2024-56606",
    "CVE-2024-56607",
    "CVE-2024-56609",
    "CVE-2024-56611",
    "CVE-2024-56614",
    "CVE-2024-56615",
    "CVE-2024-56616",
    "CVE-2024-56617",
    "CVE-2024-56619",
    "CVE-2024-56620",
    "CVE-2024-56622",
    "CVE-2024-56623",
    "CVE-2024-56625",
    "CVE-2024-56629",
    "CVE-2024-56630",
    "CVE-2024-56631",
    "CVE-2024-56632",
    "CVE-2024-56634",
    "CVE-2024-56635",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56641",
    "CVE-2024-56642",
    "CVE-2024-56643",
    "CVE-2024-56644",
    "CVE-2024-56645",
    "CVE-2024-56648",
    "CVE-2024-56649",
    "CVE-2024-56651",
    "CVE-2024-56654",
    "CVE-2024-56656",
    "CVE-2024-56659",
    "CVE-2024-56660",
    "CVE-2024-56661",
    "CVE-2024-56662",
    "CVE-2024-56663",
    "CVE-2024-56664",
    "CVE-2024-56667",
    "CVE-2024-56670",
    "CVE-2024-56672",
    "CVE-2024-56675",
    "CVE-2024-56677",
    "CVE-2024-56678",
    "CVE-2024-56681",
    "CVE-2024-56683",
    "CVE-2024-56687",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56691",
    "CVE-2024-56694",
    "CVE-2024-56698",
    "CVE-2024-56700",
    "CVE-2024-56701",
    "CVE-2024-56704",
    "CVE-2024-56705",
    "CVE-2024-56708",
    "CVE-2024-56709",
    "CVE-2024-56712",
    "CVE-2024-56716",
    "CVE-2024-56722",
    "CVE-2024-56723",
    "CVE-2024-56724",
    "CVE-2024-56729",
    "CVE-2024-56739",
    "CVE-2024-56741",
    "CVE-2024-56745",
    "CVE-2024-56746",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56752",
    "CVE-2024-56754",
    "CVE-2024-56755",
    "CVE-2024-56756",
    "CVE-2024-56759",
    "CVE-2024-56760",
    "CVE-2024-56765",
    "CVE-2024-56766",
    "CVE-2024-56767",
    "CVE-2024-56769",
    "CVE-2024-56774",
    "CVE-2024-56775",
    "CVE-2024-56776",
    "CVE-2024-56777",
    "CVE-2024-56778",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-56787",
    "CVE-2024-57791",
    "CVE-2024-57792",
    "CVE-2024-57793",
    "CVE-2024-57795",
    "CVE-2024-57798",
    "CVE-2024-57801",
    "CVE-2024-57804",
    "CVE-2024-57809",
    "CVE-2024-57838",
    "CVE-2024-57849",
    "CVE-2024-57850",
    "CVE-2024-57857",
    "CVE-2024-57874",
    "CVE-2024-57876",
    "CVE-2024-57887",
    "CVE-2024-57888",
    "CVE-2024-57890",
    "CVE-2024-57892",
    "CVE-2024-57893",
    "CVE-2024-57896",
    "CVE-2024-57897",
    "CVE-2024-57899",
    "CVE-2024-57903",
    "CVE-2024-57904",
    "CVE-2024-57906",
    "CVE-2024-57907",
    "CVE-2024-57908",
    "CVE-2024-57910",
    "CVE-2024-57911",
    "CVE-2024-57912",
    "CVE-2024-57913",
    "CVE-2024-57915",
    "CVE-2024-57916",
    "CVE-2024-57922",
    "CVE-2024-57926",
    "CVE-2024-57929",
    "CVE-2024-57932",
    "CVE-2024-57933",
    "CVE-2024-57935",
    "CVE-2024-57936",
    "CVE-2024-57940",
    "CVE-2025-21632",
    "CVE-2025-21645",
    "CVE-2025-21646",
    "CVE-2025-21649",
    "CVE-2025-21650",
    "CVE-2025-21651",
    "CVE-2025-21656",
    "CVE-2025-21662"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0289-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2025:0289-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:0289-1 advisory.

    The SUSE Linux Enterprise 15 SP6 Confidential Computing kernel was updated to receive various security
    bugfixes.


    The following security bugs were fixed:

    - CVE-2023-52489: mm/sparsemem: fix race in accessing memory_section->usage (bsc#1221326).
    - CVE-2024-26596: net: dsa: fix netdev_priv() dereference before check on non-DSA netdevice events
    (bsc#1220355).
    - CVE-2024-26924: scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (bsc#1225820).
    - CVE-2024-27397: netfilter: nf_tables: use timestamp to check for set element timeout (bsc#1224095).
    - CVE-2024-35839: kABI fix for netfilter: bridge: replace physindev with physinif in nf_bridge_info
    (bsc#1224726).
    - CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies (bsc#1225758).
    - CVE-2024-41042: Prefer nft_chain_validate (bsc#1228526).
    - CVE-2024-44934: net: bridge: mcast: wait for previous gc cycles when removing port (bsc#1229809).
    - CVE-2024-44996: vsock: fix recursive ->recvmsg calls (bsc#1230205).
    - CVE-2024-45828: i3c: mipi-i3c-hci: Mask ring interrupts before ring stop request (bsc#1235705).
    - CVE-2024-46680: Bluetooth: btnxpuart: Fix random crash seen while removing driver (bsc#1230557).
    - CVE-2024-46765: ice: protect XDP configuration with a mutex (bsc#1230807).
    - CVE-2024-46800: sch/netem: fix use after free in netem_dequeue (bsc#1230827).
    - CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).
    - CVE-2024-48881: bcache: revert replacing IS_ERR_OR_NULL with IS_ERR again (bsc#1235727).
    - CVE-2024-49944: sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (bsc#1232166).
    - CVE-2024-49951: Bluetooth: MGMT: Fix possible crash on mgmt_index_removed (bsc#1232158).
    - CVE-2024-49952: netfilter: nf_tables: prevent nf_skb_duplicated corruption (bsc#1232157).
    - CVE-2024-49998: net: dsa: improve shutdown sequence (bsc#1232087).
    - CVE-2024-50018: net: napi: Prevent overflow of napi_defer_hard_irqs (bsc#1232419).
    - CVE-2024-50039: kABI: Restore deleted EXPORT_SYMBOL(__qdisc_calculate_pkt_len) (bsc#1231909).
    - CVE-2024-50143: udf: fix uninit-value use in udf_get_fileshortad (bsc#1233038).
    - CVE-2024-50151: smb: client: fix OOBs when building SMB2_IOCTL request (bsc#1233055).
    - CVE-2024-50199: mm/swapfile: skip HugeTLB pages for unuse_vma (bsc#1233112).
    - CVE-2024-50202: nilfs2: propagate directory read errors from nilfs_find_entry() (bsc#1233324).
    - CVE-2024-50252: mlxsw: spectrum_ipip: Fix memory leak when changing remote IPv6 address (bsc#1233201).
    - CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6() (bsc#1233200).
    - CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key() (bsc#1233239).
    - CVE-2024-50278, CVE-2024-50280: dm cache: fix flushing uninitialized delayed_work on cache_ctr error
    (bsc#1233467 bsc#1233469).
    - CVE-2024-50278: dm cache: fix potential out-of-bounds access on the first resume (bsc#1233467).
    - CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when resizing (bsc#1233468).
    - CVE-2024-50296: net: hns3: fix kernel crash when uninstalling driver (bsc#1233485).
    - CVE-2024-50299: sctp: properly validate chunk size in sctp_sf_ootb() (bsc#1233488).
    - CVE-2024-53043: mctp i2c: handle NULL header address (bsc#1233523).
    - CVE-2024-53050: drm/i915/hdcp: Add encoder check in hdcp2_get_capability (bsc#1233546).
    - CVE-2024-53051: drm/i915/hdcp: Add encoder check in intel_hdcp_get_capability (bsc#1233547).
    - CVE-2024-53055: wifi: iwlwifi: mvm: fix 6 GHz scan construction (bsc#1233550).
    - CVE-2024-53056: drm/mediatek: Fix potential NULL dereference in mtk_crtc_destroy() (bsc#1233568).
    - CVE-2024-53064: idpf: fix idpf_vc_core_init error path (bsc#1233558 bsc#1234464).
    - CVE-2024-53090: afs: Fix lock recursion (bsc#1233637).
    - CVE-2024-53091: bpf: Add sk_is_inet and IS_ICSK check in tls_sw_has_ctx_tx/rx (bsc#1233638).
    - CVE-2024-53099: bpf: Check validity of link->type in bpf_link_show_fdinfo() (bsc#1233772).
    - CVE-2024-53105: mm: page_alloc: move mlocked flag clearance into free_pages_prepare() (bsc#1234069).
    - CVE-2024-53110: vp_vdpa: fix id_table array not null terminated error (bsc#1234085).
    - CVE-2024-53111: mm/mremap: fix address wraparound in move_page_tables() (bsc#1234086).
    - CVE-2024-53113: mm: fix NULL pointer dereference in alloc_pages_bulk_noprof (bsc#1234077).
    - CVE-2024-53117: virtio/vsock: Improve MSG_ZEROCOPY error handling (bsc#1234079).
    - CVE-2024-53118: vsock: Fix sk_error_queue memory leak (bsc#1234071).
    - CVE-2024-53119: virtio/vsock: Fix accept_queue memory leak (bsc#1234073).
    - CVE-2024-53121: net/mlx5: fs, lock FTE when checking if active (bsc#1234078).
    - CVE-2024-53122: mptcp: cope racing subflow creation in mptcp_rcv_space_adjust (bsc#1234076).
    - CVE-2024-53125: bpf: sync_linked_regs() must preserve subreg_def (bsc#1234156).
    - CVE-2024-53130: nilfs2: fix null-ptr-deref in block_dirty_buffer tracepoint (bsc#1234219).
    - CVE-2024-53131: nilfs2: fix null-ptr-deref in block_touch_buffer tracepoint (bsc#1234220).
    - CVE-2024-53133: drm/amd/display: Handle dml allocation failure to avoid crash (bsc#1234221)
    - CVE-2024-53134: pmdomain: imx93-blk-ctrl: correct remove path (bsc#1234159).
    - CVE-2024-53138: net/mlx5e: kTLS, Fix incorrect page refcounting (bsc#1234223).
    - CVE-2024-53141: netfilter: ipset: add missing range check in bitmap_ip_uadt (bsc#1234381).
    - CVE-2024-53160: rcu/kvfree: Fix data-race in __mod_timer / kvfree_call_rcu (bsc#1234810).
    - CVE-2024-53161: EDAC/bluefield: Fix potential integer overflow (bsc#1234856).
    - CVE-2024-53164: net: sched: fix ordering of qlen adjustment (bsc#1234863).
    - CVE-2024-53170: block: fix uaf for flush rq while iterating tags (bsc#1234888).
    - CVE-2024-53172: ubi: fastmap: Fix duplicate slab cache names while attaching (bsc#1234898).
    - CVE-2024-53175: ipc: fix memleak if msg_init_ns failed in create_ipc_ns (bsc#1234893).
    - CVE-2024-53179: smb: client: fix use-after-free of signing key (bsc#1234921).
    - CVE-2024-53185: smb: client: fix NULL ptr deref in crypto_aead_setkey() (bsc#1234901).
    - CVE-2024-53195: KVM: arm64: Get rid of userspace_irqchip_in_use (bsc#1234957).
    - CVE-2024-53196: KVM: arm64: Do not retire aborted MMIO instruction (bsc#1234906).
    - CVE-2024-53198: xen: Fix the issue of resource not being properly released in xenbus_dev_probe()
    (bsc#1234923).
    - CVE-2024-53214: vfio/pci: Properly hide first-in-list PCIe extended capability (bsc#1235004).
    - CVE-2024-53216: nfsd: fix UAF when access ex_uuid or ex_stats (bsc#1235003).
    - CVE-2024-53222: zram: fix NULL pointer in comp_algorithm_show() (bsc#1234974).
    - CVE-2024-53227: scsi: bfa: Fix use-after-free in bfad_im_module_exit() (bsc#1235011).
    - CVE-2024-53232: iommu/s390: Implement blocking domain (bsc#1235050).
    - CVE-2024-53234: erofs: handle NONHEAD !delta[1] lclusters gracefully (bsc#1235045).
    - CVE-2024-53236: xsk: Free skb when TX metadata options are invalid (bsc#1235000).
    - CVE-2024-53240: xen/netfront: fix crash when removing device (bsc#1234281).
    - CVE-2024-53241: x86/xen: use new hypercall functions instead of hypercall page (XSA-466 bsc#1234282).
    - CVE-2024-53685: ceph: give up on paths longer than PATH_MAX (bsc#1235720).
    - CVE-2024-55639: net: renesas: rswitch: avoid use-after-put for a device tree node (bsc#1235737).
    - CVE-2024-55881: KVM: x86: Play nice with protected guests in complete_hypercall_exit() (bsc#1235745).
    - CVE-2024-56372: net: tun: fix tun_napi_alloc_frags() (bsc#1235753).
    - CVE-2024-56549: cachefiles: Fix NULL pointer dereference in object->file (bsc#1234912).
    - CVE-2024-56566: mm/slub: Avoid list corruption when removing a slab from the full list (bsc#1235033).
    - CVE-2024-56568: iommu/arm-smmu: Defer probe of clients after smmu device bound (bsc#1235032).
    - CVE-2024-56569: ftrace: Fix regression with module command in stack_trace_filter (bsc#1235031).
    - CVE-2024-56570: ovl: Filter invalid inodes with missing lookup function (bsc#1235035).
    - CVE-2024-56582: btrfs: fix use-after-free in btrfs_encoded_read_endio() (bsc#1235128).
    - CVE-2024-56588: scsi: hisi_sas: Create all dump files during debugfs initialization (bsc#1235123).
    - CVE-2024-56589: scsi: hisi_sas: Add cond_resched() for no forced preemption model (bsc#1235241).
    - CVE-2024-56599: wifi: ath10k: avoid NULL pointer error during sdio remove (bsc#1235138).
    - CVE-2024-56602: net: ieee802154: do not leave a dangling sk pointer in ieee802154_create()
    (bsc#1235521).
    - CVE-2024-56603: net: af_can: do not leave a dangling sk pointer in can_create() (bsc#1235415).
    - CVE-2024-56604: Bluetooth: RFCOMM: avoid leaving dangling sk pointer in rfcomm_sock_alloc()
    (bsc#1235056).
    - CVE-2024-56605: Bluetooth: L2CAP: do not leave dangling sk pointer on error in l2cap_sock_create()
    (bsc#1235061).
    - CVE-2024-56611: mm/mempolicy: fix migrate_to_node() assuming there is at least one VMA in a MM
    (bsc#1235391).
    - CVE-2024-56614: xsk: fix OOB map writes when deleting elements (bsc#1235424).
    - CVE-2024-56615: bpf: fix OOB devmap writes when deleting elements (bsc#1235426).
    - CVE-2024-56617: cacheinfo: Allocate memory during CPU hotplug if not done from the primary CPU
    (bsc#1235429).
    - CVE-2024-56620: scsi: ufs: qcom: Only free platform MSIs when ESI is enabled (bsc#1235227).
    - CVE-2024-56622: scsi: ufs: core: sysfs: Prevent div by zero (bsc#1235251).
    - CVE-2024-56631: scsi: sg: Fix slab-use-after-free read in sg_release() (bsc#1235480).
    - CVE-2024-56635: net: avoid potential UAF in default_operstate() (bsc#1235519).
    - CVE-2024-56636: geneve: do not assume mac header is set in geneve_xmit_skb() (bsc#1235520).
    - CVE-2024-56637: netfilter: ipset: Hold module reference while requesting a module (bsc#1235523).
    - CVE-2024-56641: net/smc: initialize close_work early to avoid warning (bsc#1235526).
    - CVE-2024-56643: dccp: Fix memory leak in dccp_feat_change_recv (bsc#1235132).
    - CVE-2024-56648: net: hsr: avoid potential out-of-bound access in fill_frame_info() (bsc#1235451).
    - CVE-2024-56649: net: enetc: Do not configure preemptible TCs if SIs do not support (bsc#1235449).
    - CVE-2024-56656: bnxt_en: Fix aggregation ID mask to prevent oops on 5760X chips (bsc#1235444).
    - CVE-2024-56659: net: lapb: increase LAPB_HEADER_LEN (bsc#1235439).
    - CVE-2024-56660: net/mlx5: DR, prevent potential error pointer dereference (bsc#1235437).
    - CVE-2024-56664: bpf, sockmap: Fix race between element replace and close() (bsc#1235249).
    - CVE-2024-56675: bpf: Fix UAF via mismatching bpf_prog/attachment RCU flavors (bsc#1235555).
    - CVE-2024-56694: bpf: fix recursive lock when verdict program return SK_PASS (bsc#1235412).
    - CVE-2024-56704: 9p/xen: fix release of IRQ (bsc#1235584).
    - CVE-2024-56708: EDAC/igen6: Avoid segmentation fault on module unload (bsc#1235564).
    - CVE-2024-56712: udmabuf: fix memory leak on last export_udmabuf() error path (bsc#1235565).
    - CVE-2024-56716: netdevsim: prevent bad user input in nsim_dev_health_break_write() (bsc#1235587).
    - CVE-2024-56729: smb: Initialize cfid->tcon before performing network ops (bsc#1235503).
    - CVE-2024-56747: scsi: qedi: Fix a possible memory leak in qedi_alloc_and_init_sb() (bsc#1234934).
    - CVE-2024-56748: scsi: qedf: Fix a possible memory leak in qedf_alloc_and_init_sb() (bsc#1235627).
    - CVE-2024-56755: netfs/fscache: Add a memory barrier for FSCACHE_VOLUME_CREATING (bsc#1234920).
    - CVE-2024-56759: btrfs: fix use-after-free when COWing tree bock and tracing is enabled (bsc#1235645).
    - CVE-2024-56774: btrfs: add a sanity check for btrfs root in btrfs_search_slot() (bsc#1235653).
    - CVE-2024-56775: drm/amd/display: Fix handling of plane refcount (bsc#1235657).
    - CVE-2024-57791: net/smc: check return value of sock_recvmsg when draining clc data (bsc#1235759).
    - CVE-2024-57793: virt: tdx-guest: Just leak decrypted memory on unrecoverable errors (bsc#1235768).
    - CVE-2024-57795: RDMA/rxe: Remove the direct link to net_device (bsc#1235906).
    - CVE-2024-57801: net/mlx5e: Skip restore TC rules for vport rep without loaded flag (bsc#1235940).
    - CVE-2024-57804: scsi: mpi3mr: Fix corrupt config pages PHY state is switched in sysfs (bsc#1235779).
    - CVE-2024-57809: PCI: imx6: Fix suspend/resume support on i.MX6QDL (bsc#1235793).
    - CVE-2024-57838: s390/entry: Mark IRQ entries to fix stack depot warnings (bsc#1235798).
    - CVE-2024-57857: RDMA/siw: Remove direct link to net_device (bsc#1235946).
    - CVE-2024-57892: ocfs2: fix slab-use-after-free due to dangling pointer dqi_priv (bsc#1235964).
    - CVE-2024-57896: btrfs: flush delalloc workers queue before stopping cleaner kthread during unmount
    (bsc#1235965).
    - CVE-2024-57903: net: restrict SO_REUSEPORT to inet sockets (bsc#1235967).
    - CVE-2024-57929: dm array: fix releasing a faulty array block twice in dm_array_cursor_end (bsc#1236096).
    - CVE-2024-57932: gve: guard XDP xmit NDO on existence of xdp queues (bsc#1236190).
    - CVE-2024-57933: gve: guard XSK operations on the existence of queues (bsc#1236178).
    - CVE-2025-21632: x86/fpu: Ensure shadow stack is active before 'getting' registers (bsc#1236106).
    - CVE-2025-21649: net: hns3: fix kernel crash when 1588 is sent on HIP08 devices (bsc#1236143).
    - CVE-2025-21650: net: hns3: fixed hclge_fetch_pf_reg accesses bar space out of bounds issue
    (bsc#1236144).
    - CVE-2025-21651: net: hns3: do not auto enable misc vector (bsc#1236145).
    - CVE-2025-21662: net/mlx5: Fix variable not being completed when function returns (bsc#1236198).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1012628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233638");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234085");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234223");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234635");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234825");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234957");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236248");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020239.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc3a3510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39282");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50256");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50272");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50278");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50299");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53050");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53111");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53121");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53138");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53164");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53169");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53170");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53172");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53174");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53175");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53190");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53195");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53198");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53227");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53231");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-54680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-55639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-55881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-55916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56372");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56557");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56568");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56573");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56716");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21662");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/03");

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
    {'reference':'kernel-coco-6.4.0-15061.12.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-coco-devel-6.4.0-15061.12.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-coco_debug-6.4.0-15061.12.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-coco_debug-devel-6.4.0-15061.12.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-devel-coco-6.4.0-15061.12.coco15sp6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-source-coco-6.4.0-15061.12.coco15sp6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'kernel-syms-coco-6.4.0-15061.12.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']},
    {'reference':'reiserfs-kmp-coco-6.4.0-15061.12.coco15sp6.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-confidential-computing-release--15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-coco / kernel-coco-devel / kernel-coco_debug / etc');
}
