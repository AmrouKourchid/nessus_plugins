#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0834-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(232643);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/12");

  script_cve_id(
    "CVE-2021-22543",
    "CVE-2021-37159",
    "CVE-2021-47634",
    "CVE-2021-47644",
    "CVE-2022-2991",
    "CVE-2022-48636",
    "CVE-2022-48650",
    "CVE-2022-48664",
    "CVE-2022-48953",
    "CVE-2022-48975",
    "CVE-2022-49006",
    "CVE-2022-49076",
    "CVE-2022-49080",
    "CVE-2022-49089",
    "CVE-2022-49124",
    "CVE-2022-49134",
    "CVE-2022-49135",
    "CVE-2022-49151",
    "CVE-2022-49178",
    "CVE-2022-49182",
    "CVE-2022-49201",
    "CVE-2022-49247",
    "CVE-2022-49490",
    "CVE-2022-49626",
    "CVE-2022-49661",
    "CVE-2023-0394",
    "CVE-2023-6606",
    "CVE-2023-52572",
    "CVE-2023-52646",
    "CVE-2023-52653",
    "CVE-2023-52853",
    "CVE-2023-52924",
    "CVE-2024-23307",
    "CVE-2024-26810",
    "CVE-2024-26929",
    "CVE-2024-26930",
    "CVE-2024-26931",
    "CVE-2024-27054",
    "CVE-2024-27388",
    "CVE-2024-27397",
    "CVE-2024-47701",
    "CVE-2024-49867",
    "CVE-2024-49884",
    "CVE-2024-49950",
    "CVE-2024-49963",
    "CVE-2024-49975",
    "CVE-2024-50036",
    "CVE-2024-50067",
    "CVE-2024-50073",
    "CVE-2024-50115",
    "CVE-2024-50251",
    "CVE-2024-50304",
    "CVE-2024-53173",
    "CVE-2024-53217",
    "CVE-2024-53239",
    "CVE-2024-56539",
    "CVE-2024-56548",
    "CVE-2024-56605",
    "CVE-2024-56633",
    "CVE-2024-56647",
    "CVE-2024-56658",
    "CVE-2024-56688",
    "CVE-2024-57896",
    "CVE-2025-21638",
    "CVE-2025-21639",
    "CVE-2025-21640",
    "CVE-2025-21673",
    "CVE-2025-21689",
    "CVE-2025-21690",
    "CVE-2025-21700",
    "CVE-2025-21753"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0834-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2025:0834-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:0834-1 advisory.

    The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2021-22543: Fixed improper handling of VM_IO|VM_PFNMAP vmas in KVM (bsc#1186482).
    - CVE-2021-47634: ubi: Fix race condition between ctrl_cdev_ioctl and ubi_cdev_ioctl (bsc#1237758).
    - CVE-2021-47644: media: staging: media: zoran: move videodev alloc (bsc#1237766).
    - CVE-2022-48953: rtc: cmos: fix build on non-ACPI platforms (bsc#1231941).
    - CVE-2022-48975: gpiolib: fix memory leak in gpiochip_setup_dev() (bsc#1231885).
    - CVE-2022-49006: tracing: Free buffers when a used dynamic event is removed (bsc#1232163).
    - CVE-2022-49076: RDMA/hfi1: Fix use-after-free bug for mm struct (bsc#1237738).
    - CVE-2022-49080: mm/mempolicy: fix mpol_new leak in shared_policy_replace (bsc#1238033).
    - CVE-2022-49089: IB/rdmavt: add lock to call to rvt_error_qp to prevent a race condition (bsc#1238041).
    - CVE-2022-49124: x86/mce: Work around an erratum on fast string copy instructions (bsc#1238148).
    - CVE-2022-49134: mlxsw: spectrum: Guard against invalid local ports (bsc#1237982).
    - CVE-2022-49135: drm/amd/display: Fix memory leak (bsc#1238006).
    - CVE-2022-49151: can: mcba_usb: properly check endpoint type (bsc#1237778).
    - CVE-2022-49178: memstick/mspro_block: fix handling of read-only devices (bsc#1238107).
    - CVE-2022-49182: net: hns3: add vlan list lock to protect vlan list (bsc#1238260).
    - CVE-2022-49201: ibmvnic: fix race between xmit and reset (bsc#1238256).
    - CVE-2022-49247: media: stk1160: If start stream fails, return buffers with VB2_BUF_STATE_QUEUED
    (bsc#1237783).
    - CVE-2022-49490: drm/msm/mdp5: Return error code in mdp5_pipe_release when deadlock is (bsc#1238275).
    - CVE-2022-49626: sfc: fix use after free when disabling sriov (bsc#1238270).
    - CVE-2022-49661: can: gs_usb: gs_usb_open/close(): fix memory leak (bsc#1237788).
    - CVE-2023-52572: Fixed UAF in cifs_demultiplex_thread() in cifs (bsc#1220946).
    - CVE-2023-52853: hid: cp2112: Fix duplicate workqueue initialization (bsc#1224988).
    - CVE-2023-52924: netfilter: nf_tables: do not skip expired elements during walk (bsc#1236821).
    - CVE-2023-6606: Fixed an out of bounds read in the SMB client when receiving a malformed length from a
    server (bsc#1217947).
    - CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5
    modules (bsc#1219169).
    - CVE-2024-27397: netfilter: nf_tables: use timestamp to check for set element timeout (bsc#1224095).
    - CVE-2024-49963: mailbox: bcm2835: Fix timeout during suspend mode (bsc#1232147).
    - CVE-2024-49975: uprobes: fix kernel info leak via '[uprobes]' vma (bsc#1232104).
    - CVE-2024-50036: net: do not delay dst_entries_add() in dst_release() (bsc#1231912).
    - CVE-2024-50067: uprobe: avoid out-of-bounds memory access of fetching args (bsc#1232416).
    - CVE-2024-50251: netfilter: nft_payload: sanitize offset and length before calling skb_checksum()
    (bsc#1233248).
    - CVE-2024-50304: ipv4: ip_tunnel: Fix suspicious RCU usage warning in ip_tunnel_find() (bsc#1233522).
    - CVE-2024-53217: nfsd: restore callback functionality for NFSv4.0 (bsc#1234999).
    - CVE-2024-56633: bpf, sockmap: Fix repeated calls to sock_put() when msg has more_data (bsc#1235485).
    - CVE-2024-56647: net: Fix icmp host relookup triggering ip_rt_bug (bsc#1235435).
    - CVE-2024-56658: net: defer final 'struct net' free in netns dismantle (bsc#1235441).
    - CVE-2024-56688: sunrpc: clear XPRT_SOCK_UPD_TIMEOUT when reset transport (bsc#1235538).
    - CVE-2025-21638: sctp: sysctl: auth_enable: avoid using current->nsproxy (bsc#1236115).
    - CVE-2025-21639: sctp: sysctl: rto_min/max: avoid using current->nsproxy (bsc#1236122).
    - CVE-2025-21640: sctp: sysctl: cookie_hmac_alg: avoid using current->nsproxy (bsc#1236123).
    - CVE-2025-21673: smb: client: fix double free of TCP_Server_Info::hostname (bsc#1236689).
    - CVE-2025-21689: USB: serial: quatech2: fix null-ptr-deref in qt2_process_read_urb() (bsc#1237017).
    - CVE-2025-21690: scsi: storvsc: Ratelimit warning logs to prevent VM denial of service (bsc#1237025).
    - CVE-2025-21700: net: sched: Disallow replacing of child qdisc from one parent to another (bsc#1237159).
    - CVE-2025-21753: btrfs: fix use-after-free when attempting to join an aborted transaction (bsc#1237875).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1050081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1051510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1100823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1101669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1104731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1113295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1120902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238275");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-March/020497.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60032dae");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49178");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50251");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21753");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22543");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-57896");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/12");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_250-default");
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
    {'reference':'kernel-default-kgraft-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_250-default-1-8.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.250.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.250.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.250.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.250.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.250.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.250.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.250.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.250.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.250.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.250.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
      severity   : SECURITY_WARNING,
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
