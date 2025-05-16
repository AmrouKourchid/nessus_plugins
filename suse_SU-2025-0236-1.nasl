#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0236-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214781);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2022-48742",
    "CVE-2022-49033",
    "CVE-2022-49035",
    "CVE-2023-52434",
    "CVE-2023-52922",
    "CVE-2024-5660",
    "CVE-2024-8805",
    "CVE-2024-26976",
    "CVE-2024-35847",
    "CVE-2024-36484",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-38589",
    "CVE-2024-41013",
    "CVE-2024-46771",
    "CVE-2024-47141",
    "CVE-2024-47666",
    "CVE-2024-47678",
    "CVE-2024-47709",
    "CVE-2024-49925",
    "CVE-2024-49944",
    "CVE-2024-50039",
    "CVE-2024-50143",
    "CVE-2024-50151",
    "CVE-2024-50166",
    "CVE-2024-50199",
    "CVE-2024-50211",
    "CVE-2024-50228",
    "CVE-2024-50256",
    "CVE-2024-50262",
    "CVE-2024-50278",
    "CVE-2024-50280",
    "CVE-2024-50287",
    "CVE-2024-50299",
    "CVE-2024-53057",
    "CVE-2024-53101",
    "CVE-2024-53112",
    "CVE-2024-53136",
    "CVE-2024-53141",
    "CVE-2024-53144",
    "CVE-2024-53146",
    "CVE-2024-53150",
    "CVE-2024-53156",
    "CVE-2024-53157",
    "CVE-2024-53172",
    "CVE-2024-53173",
    "CVE-2024-53179",
    "CVE-2024-53198",
    "CVE-2024-53210",
    "CVE-2024-53214",
    "CVE-2024-53224",
    "CVE-2024-53239",
    "CVE-2024-53240",
    "CVE-2024-56531",
    "CVE-2024-56548",
    "CVE-2024-56551",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56587",
    "CVE-2024-56599",
    "CVE-2024-56603",
    "CVE-2024-56604",
    "CVE-2024-56605",
    "CVE-2024-56606",
    "CVE-2024-56616",
    "CVE-2024-56631",
    "CVE-2024-56642",
    "CVE-2024-56664",
    "CVE-2024-56704",
    "CVE-2024-56724",
    "CVE-2024-56756",
    "CVE-2024-57791",
    "CVE-2024-57849",
    "CVE-2024-57887",
    "CVE-2024-57888",
    "CVE-2024-57892",
    "CVE-2024-57893"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0236-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2025:0236-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:0236-1 advisory.

    The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2022-48742: rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink() (bsc#1226694).
    - CVE-2022-49033: btrfs: qgroup: fix sleep from invalid context bug in btrfs_qgroup_inherit()
    (bsc#1232045).
    - CVE-2022-49035: media: s5p_cec: limit msg.len to CEC_MAX_MSG_SIZE (bsc#1215304).
    - CVE-2023-52434: Fixed potential OOBs in smb2_parse_contexts()  (bsc#1220148).
    - CVE-2023-52922: can: bcm: Fix UAF in bcm_proc_show() (bsc#1233977).
    - CVE-2024-26976: KVM: Always flush async #PF workqueue when vCPU is being destroyed (bsc#1223635).
    - CVE-2024-35847: irqchip/gic-v3-its: Prevent double free on error (bsc#1224697).
    - CVE-2024-36883: net: fix out-of-bounds access in ops_init (bsc#1225725).
    - CVE-2024-36886: tipc: fix UAF in error path (bsc#1225730).
    - CVE-2024-38589: netrom: fix possible dead-lock in nr_rt_ioctl() (bsc#1226748).
    - CVE-2024-41013: xfs: do not walk off the end of a directory data block (bsc#1228405).
    - CVE-2024-47141: pinmux: Use sequential access to access desc->pinmux data (bsc#1235708).
    - CVE-2024-47666: scsi: pm80xx: Set phy->enable_completion only when we wait for it (bsc#1231453).
    - CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).
    - CVE-2024-49944: sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (bsc#1232166).
    - CVE-2024-50039: kABI: Restore deleted EXPORT_SYMBOL(__qdisc_calculate_pkt_len) (bsc#1231909).
    - CVE-2024-50143: udf: fix uninit-value use in udf_get_fileshortad (bsc#1233038).
    - CVE-2024-50151: smb: client: fix OOBs when building SMB2_IOCTL request (bsc#1233055).
    - CVE-2024-50166: fsl/fman: Fix refcount handling of fman-related devices (bsc#1233050).
    - CVE-2024-50199: mm/swapfile: skip HugeTLB pages for unuse_vma (bsc#1233112).
    - CVE-2024-50211: udf: refactor inode_bmap() to handle error (bsc#1233096).
    - CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6() (bsc#1233200).
    - CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key() (bsc#1233239).
    - CVE-2024-50287: media: v4l2-tpg: prevent the risk of a division by zero (bsc#1233476).
    - CVE-2024-50299: sctp: properly validate chunk size in sctp_sf_ootb() (bsc#1233488).
    - CVE-2024-53057: net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT (bsc#1233551).
    - CVE-2024-53101: fs: Fix uninitialized value issue in from_kuid and from_kgid (bsc#1233769).
    - CVE-2024-53141: netfilter: ipset: add missing range check in bitmap_ip_uadt (bsc#1234381).
    - CVE-2024-53146: NFSD: Prevent a potential integer overflow (bsc#1234853).
    - CVE-2024-53150: ALSA: usb-audio: Fix out of bounds reads when finding clock sources (bsc#1234834).
    - CVE-2024-53156: wifi: ath9k: add range check for conn_rsp_epid in htc_connect_service() (bsc#1234846).
    - CVE-2024-53157: firmware: arm_scpi: Check the DVFS OPP count returned by the firmware (bsc#1234827).
    - CVE-2024-53172: ubi: fastmap: Fix duplicate slab cache names while attaching (bsc#1234898).
    - CVE-2024-53173: NFSv4.0: Fix a use-after-free problem in the asynchronous open() (bsc#1234891).
    - CVE-2024-53179: smb: client: fix use-after-free of signing key (bsc#1234921).
    - CVE-2024-53198: xen: Fix the issue of resource not being properly released in xenbus_dev_probe()
    (bsc#1234923).
    - CVE-2024-53210: s390/iucv: MSG_PEEK causes memory leak in iucv_sock_destruct() (bsc#1234971).
    - CVE-2024-53214: vfio/pci: Properly hide first-in-list PCIe extended capability (bsc#1235004).
    - CVE-2024-53224: RDMA/mlx5: Cancel pkey work before destroying device resources (bsc#1235009).
    - CVE-2024-53239: ALSA: 6fire: Release resources at card release (bsc#1235054).
    - CVE-2024-53240: xen/netfront: fix crash when removing device (bsc#1234281).
    - CVE-2024-56531: ALSA: caiaq: Use snd_card_free_when_closed() at disconnection (bsc#1235057).
    - CVE-2024-56548: hfsplus: do not query the device logical block size multiple times (bsc#1235073).
    - CVE-2024-56551: drm/amdgpu: fix usage slab after free (bsc#1235075).
    - CVE-2024-56569: ftrace: Fix regression with module command in stack_trace_filter (bsc#1235031).
    - CVE-2024-56570: ovl: Filter invalid inodes with missing lookup function (bsc#1235035).
    - CVE-2024-56587: leds: class: Protect brightness_show() with led_cdev->led_access mutex (bsc#1235125).
    - CVE-2024-56599: wifi: ath10k: avoid NULL pointer error during sdio remove (bsc#1235138).
    - CVE-2024-56603: net: af_can: do not leave a dangling sk pointer in can_create() (bsc#1235415).
    - CVE-2024-56604: Bluetooth: RFCOMM: avoid leaving dangling sk pointer in rfcomm_sock_alloc()
    (bsc#1235056).
    - CVE-2024-56605: Bluetooth: L2CAP: do not leave dangling sk pointer on error in l2cap_sock_create()
    (bsc#1235061).
    - CVE-2024-56616: drm/dp_mst: Fix MST sideband message body length check (bsc#1235427).
    - CVE-2024-56631: scsi: sg: Fix slab-use-after-free read in sg_release() (bsc#1235480).
    - CVE-2024-56642: tipc: Fix use-after-free of kernel socket in cleanup_bearer() (bsc#1235433).
    - CVE-2024-56664: bpf, sockmap: Fix race between element replace and close() (bsc#1235249).
    - CVE-2024-56704: 9p/xen: fix release of IRQ (bsc#1235584).
    - CVE-2024-56724: mfd: intel_soc_pmic_bxtwc: Use IRQ domain for TMU device (bsc#1235577).
    - CVE-2024-56756: nvme-pci: fix freeing of the HMB descriptor table (bsc#1234922).
    - CVE-2024-57791: net/smc: check return value of sock_recvmsg when draining clc data (bsc#1235759).
    - CVE-2024-57849: s390/cpum_sf: Handle CPU hotplug remove during sampling (bsc#1235814).
    - CVE-2024-57887: drm: adv7511: Fix use-after-free in adv7533_attach_dsi() (bsc#1235952).
    - CVE-2024-57888: workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker
    (bsc#1235416 bsc#1235918).
    - CVE-2024-57892: ocfs2: fix slab-use-after-free due to dangling pointer dqi_priv (bsc#1235964).
    - CVE-2024-57893: ALSA: seq: oss: Fix races at processing SysEx messages (bsc#1235920).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235964");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020196.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5661a68");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50256");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50278");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50299");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53136");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53172");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57893");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_244-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-kgraft-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_244-default-1-8.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.244.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.244.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.244.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.244.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.244.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.244.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.244.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.244.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.244.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.244.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
