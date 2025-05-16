#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0201-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(232634);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2021-47202",
    "CVE-2022-36280",
    "CVE-2022-48742",
    "CVE-2022-49033",
    "CVE-2022-49035",
    "CVE-2023-1382",
    "CVE-2023-33951",
    "CVE-2023-33952",
    "CVE-2023-52920",
    "CVE-2024-8805",
    "CVE-2024-24860",
    "CVE-2024-26886",
    "CVE-2024-26924",
    "CVE-2024-36915",
    "CVE-2024-42232",
    "CVE-2024-44934",
    "CVE-2024-47666",
    "CVE-2024-47678",
    "CVE-2024-49944",
    "CVE-2024-49952",
    "CVE-2024-50018",
    "CVE-2024-50143",
    "CVE-2024-50154",
    "CVE-2024-50166",
    "CVE-2024-50181",
    "CVE-2024-50202",
    "CVE-2024-50211",
    "CVE-2024-50256",
    "CVE-2024-50262",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50280",
    "CVE-2024-50296",
    "CVE-2024-53051",
    "CVE-2024-53055",
    "CVE-2024-53056",
    "CVE-2024-53064",
    "CVE-2024-53072",
    "CVE-2024-53090",
    "CVE-2024-53095",
    "CVE-2024-53101",
    "CVE-2024-53113",
    "CVE-2024-53114",
    "CVE-2024-53119",
    "CVE-2024-53120",
    "CVE-2024-53122",
    "CVE-2024-53125",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53142",
    "CVE-2024-53146",
    "CVE-2024-53150",
    "CVE-2024-53156",
    "CVE-2024-53157",
    "CVE-2024-53158",
    "CVE-2024-53161",
    "CVE-2024-53162",
    "CVE-2024-53173",
    "CVE-2024-53179",
    "CVE-2024-53206",
    "CVE-2024-53210",
    "CVE-2024-53213",
    "CVE-2024-53214",
    "CVE-2024-53239",
    "CVE-2024-53240",
    "CVE-2024-53241",
    "CVE-2024-56539",
    "CVE-2024-56548",
    "CVE-2024-56549",
    "CVE-2024-56570",
    "CVE-2024-56571",
    "CVE-2024-56575",
    "CVE-2024-56598",
    "CVE-2024-56604",
    "CVE-2024-56605",
    "CVE-2024-56619",
    "CVE-2024-56755"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0201-2");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2025:0201-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0201-2 advisory.

    The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2022-36280: Fixed out-of-bounds memory access vulnerability found in vmwgfx driver (bsc#1203332).
    - CVE-2022-48742: rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink() (bsc#1226694).
    - CVE-2022-49033: btrfs: qgroup: fix sleep from invalid context bug in btrfs_qgroup_inherit()
    (bsc#1232045).
    - CVE-2023-1382: Fixed denial of service in tipc_conn_close (bsc#1209288).
    - CVE-2023-33951: Fixed a race condition that could have led to an information disclosure inside the
    vmwgfx driver (bsc#1211593).
    - CVE-2023-33952: Fixed a double free that could have led to a local privilege escalation inside the
    vmwgfx driver (bsc#1211595).
    - CVE-2023-52920: bpf: support non-r10 register spill/fill to/from stack in precision tracking
    (bsc#1232823).
    - CVE-2024-26886: Bluetooth: af_bluetooth: Fix deadlock (bsc#1223044).
    - CVE-2024-26924: scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (bsc#1225820).
    - CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies (bsc#1225758).
    - CVE-2024-44934: net: bridge: mcast: wait for previous gc cycles when removing port (bsc#1229809).
    - CVE-2024-47666: scsi: pm80xx: Set phy->enable_completion only when we wait for it (bsc#1231453).
    - CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).
    - CVE-2024-49944: sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (bsc#1232166).
    - CVE-2024-49952: netfilter: nf_tables: prevent nf_skb_duplicated corruption (bsc#1232157).
    - CVE-2024-50018: net: napi: Prevent overflow of napi_defer_hard_irqs (bsc#1232419).
    - CVE-2024-50143: udf: fix uninit-value use in udf_get_fileshortad (bsc#1233038).
    - CVE-2024-50166: fsl/fman: Fix refcount handling of fman-related devices (bsc#1233050).
    - CVE-2024-50181: clk: imx: Remove CLK_SET_PARENT_GATE for DRAM mux for i.MX7D (bsc#1233127).
    - CVE-2024-50202: nilfs2: propagate directory read errors from nilfs_find_entry() (bsc#1233324).
    - CVE-2024-50211: udf: refactor inode_bmap() to handle error (bsc#1233096).
    - CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6() (bsc#1233200).
    - CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key() (bsc#1233239).
    - CVE-2024-50278, CVE-2024-50280: dm cache: fix flushing uninitialized delayed_work on cache_ctr error
    (bsc#1233467 bsc#1233469).
    - CVE-2024-50278: dm cache: fix potential out-of-bounds access on the first resume (bsc#1233467).
    - CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when resizing (bsc#1233468).
    - CVE-2024-50296: net: hns3: fix kernel crash when uninstalling driver (bsc#1233485).
    - CVE-2024-53051: drm/i915/hdcp: Add encoder check in intel_hdcp_get_capability (bsc#1233547).
    - CVE-2024-53055: wifi: iwlwifi: mvm: fix 6 GHz scan construction (bsc#1233550).
    - CVE-2024-53056: drm/mediatek: Fix potential NULL dereference in mtk_crtc_destroy() (bsc#1233568).
    - CVE-2024-53064: idpf: fix idpf_vc_core_init error path (bsc#1233558 bsc#1234464).
    - CVE-2024-53072: platform/x86/amd/pmc: Detect when STB is not available (bsc#1233564).
    - CVE-2024-53090: afs: Fix lock recursion (bsc#1233637).
    - CVE-2024-53095: smb: client: Fix use-after-free of network namespace (bsc#1233642).
    - CVE-2024-53101: fs: Fix uninitialized value issue in from_kuid and from_kgid (bsc#1233769).
    - CVE-2024-53113: mm: fix NULL pointer dereference in alloc_pages_bulk_noprof (bsc#1234077).
    - CVE-2024-53114: x86/CPU/AMD: Clear virtualized VMLOAD/VMSAVE on Zen4 client (bsc#1234072).
    - CVE-2024-53119: virtio/vsock: Fix accept_queue memory leak (bsc#1234073).
    - CVE-2024-53122: mptcp: cope racing subflow creation in mptcp_rcv_space_adjust (bsc#1234076).
    - CVE-2024-53125: bpf: sync_linked_regs() must preserve subreg_def (bsc#1234156).
    - CVE-2024-53130: nilfs2: fix null-ptr-deref in block_dirty_buffer tracepoint (bsc#1234219).
    - CVE-2024-53131: nilfs2: fix null-ptr-deref in block_touch_buffer tracepoint (bsc#1234220).
    - CVE-2024-53146: NFSD: Prevent a potential integer overflow (bsc#1234853).
    - CVE-2024-53150: ALSA: usb-audio: Fix out of bounds reads when finding clock sources (bsc#1234834).
    - CVE-2024-53156: wifi: ath9k: add range check for conn_rsp_epid in htc_connect_service() (bsc#1234846).
    - CVE-2024-53157: firmware: arm_scpi: Check the DVFS OPP count returned by the firmware (bsc#1234827).
    - CVE-2024-53158: soc: qcom: geni-se: fix array underflow in geni_se_clk_tbl_get() (bsc#1234811).
    - CVE-2024-53161: EDAC/bluefield: Fix potential integer overflow (bsc#1234856).
    - CVE-2024-53162: crypto: qat/qat_4xxx - fix off by one in uof_get_name() (bsc#1234843).
    - CVE-2024-53173: NFSv4.0: Fix a use-after-free problem in the asynchronous open() (bsc#1234891).
    - CVE-2024-53179: smb: client: fix use-after-free of signing key (bsc#1234921).
    - CVE-2024-53210: s390/iucv: MSG_PEEK causes memory leak in iucv_sock_destruct() (bsc#1234971).
    - CVE-2024-53213: net: usb: lan78xx: Fix double free issue with interrupt buffer allocation (bsc#1234973).
    - CVE-2024-53214: vfio/pci: Properly hide first-in-list PCIe extended capability (bsc#1235004).
    - CVE-2024-53239: ALSA: 6fire: Release resources at card release (bsc#1235054).
    - CVE-2024-53240: xen/netfront: fix crash when removing device (bsc#1234281).
    - CVE-2024-53241: x86/xen: use new hypercall functions instead of hypercall page (XSA-466 bsc#1234282).
    - CVE-2024-56539: wifi: mwifiex: Fix memcpy() field-spanning write warning in mwifiex_config_scan()
    (bsc#1234963).
    - CVE-2024-56548: hfsplus: do not query the device logical block size multiple times (bsc#1235073).
    - CVE-2024-56549: cachefiles: Fix NULL pointer dereference in object->file (bsc#1234912).
    - CVE-2024-56570: ovl: Filter invalid inodes with missing lookup function (bsc#1235035).
    - CVE-2024-56571: media: uvcvideo: Require entities to have a non-zero unique ID (bsc#1235037).
    - CVE-2024-56575: media: imx-jpeg: Ensure power suppliers be suspended before detach them (bsc#1235039).
    - CVE-2024-56598: jfs: array-index-out-of-bounds fix in dtReadFirst (bsc#1235220).
    - CVE-2024-56604: Bluetooth: RFCOMM: avoid leaving dangling sk pointer in rfcomm_sock_alloc()
    (bsc#1235056).
    - CVE-2024-56605: Bluetooth: L2CAP: do not leave dangling sk pointer on error in l2cap_sock_create()
    (bsc#1235061).
    - CVE-2024-56619: nilfs2: fix potential out-of-bounds memory access in nilfs_find_entry() (bsc#1235224).
    - CVE-2024-56755: netfs/fscache: Add a memory barrier for FSCACHE_VOLUME_CREATING (bsc#1234920).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1170891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235507");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-March/020501.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c220c550");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-33951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-33952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50256");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50278");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53122");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53213");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56755");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
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

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.91.1.150500.6.41.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.91.1.150500.6.41.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.91.1.150500.6.41.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-devel-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-macros-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-source-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-syms-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-syms-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.91.1.150500.6.41.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.91.1.150500.6.41.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.91.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.91.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
