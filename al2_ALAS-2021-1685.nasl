#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1685.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151793);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/17");

  script_cve_id(
    "CVE-2020-26558",
    "CVE-2021-0129",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-46906",
    "CVE-2021-46938",
    "CVE-2021-46939",
    "CVE-2021-46950",
    "CVE-2021-46953",
    "CVE-2021-46955",
    "CVE-2021-46959",
    "CVE-2021-46960",
    "CVE-2021-46985",
    "CVE-2021-46992",
    "CVE-2021-47006",
    "CVE-2021-47013",
    "CVE-2021-47054",
    "CVE-2021-47055",
    "CVE-2021-47078",
    "CVE-2021-47117",
    "CVE-2021-47118",
    "CVE-2021-47142",
    "CVE-2021-47145",
    "CVE-2021-47146",
    "CVE-2021-47162",
    "CVE-2021-47166",
    "CVE-2021-47168",
    "CVE-2021-47171",
    "CVE-2021-47177",
    "CVE-2021-47245",
    "CVE-2021-47254",
    "CVE-2021-47256",
    "CVE-2021-47259",
    "CVE-2021-47274",
    "CVE-2021-47280",
    "CVE-2021-29650",
    "CVE-2021-32399",
    "CVE-2021-33034",
    "CVE-2021-33624"
  );
  script_xref(name:"ALAS", value:"2021-1685");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2021-1685)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 4.14.238-182.421. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1685 advisory.

    A vulnerability was found in the bluez, where Passkey Entry protocol used in Secure Simple Pairing (SSP),
    Secure Connections (SC) and LE Secure Connections (LESC) of the Bluetooth Core Specification is vulnerable
    to an impersonation attack where an active attacker can impersonate the initiating device without any
    previous knowledge. (CVE-2020-26558)

    A flaw was found in the Linux kernel. Improper access control in BlueZ may allow an authenticated user to
    potentially enable information disclosure via adjacent access. The highest threat from this vulnerability
    is to data confidentiality and integrity. (CVE-2021-0129)

    A denial-of-service (DoS) flaw was identified  in the Linux kernel due to an incorrect memory barrier in
    xt_replace_table in net/netfilter/x_tables.c in the netfilter subsystem. (CVE-2021-29650)

    A flaw was found in the Linux kernel's handling of the removal of Bluetooth HCI controllers. This flaw
    allows an attacker with a local account to exploit a race condition, leading to corrupted memory and
    possible privilege escalation. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-32399)

    A use-after-free flaw was found in hci_send_acl in the bluetooth host controller interface (HCI) in Linux
    kernel, where a local attacker with an access rights could cause a denial of service problem on the system
    The issue results from the object hchan, freed in hci_disconn_loglink_complete_evt, yet still used in
    other places. The highest threat from this vulnerability is to data integrity, confidentiality and system
    availability. (CVE-2021-33034)

    In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because
    of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a
    side-channel attack, aka CID-9183671af6db. (CVE-2021-33624)

    A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. (CVE-2021-3564)

    A flaw use-after-free in function hci_sock_bound_ioctl() of the Linux kernel HCI subsystem was found in
    the way user calls ioct HCIUNBLOCKADDR or other way triggers race condition of the call
    hci_unregister_dev() together with one of the calls hci_sock_blacklist_add(), hci_sock_blacklist_del(),
    hci_get_conn_info(), hci_get_auth_info(). A privileged local user could use this flaw to crash the system
    or escalate their privileges on the system. (CVE-2021-3573)

    In the Linux kernel, the following vulnerability has been resolved:

    HID: usbhid: fix info leak in hid_submit_ctrl

    In hid_submit_ctrl(), the way of calculating the report length doesn'ttake into account that report->size
    can be zero. When running thesyzkaller reproducer, a report of size 0 causes hid_submit_ctrl) tocalculate
    transfer_buffer_length as 16384. When this urb is passed tothe usb core layer, KMSAN reports an info leak
    of 16384 bytes.

    To fix this, first modify hid_report_len() to account for the zeroreport size case by using DIV_ROUND_UP
    for the division. Then, call itfrom hid_submit_ctrl(). (CVE-2021-46906)

    In the Linux kernel, the following vulnerability has been resolved:

    dm rq: fix double free of blk_mq_tag_set in dev remove after table load fails (CVE-2021-46938)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Restructure trace_clock_global() to never block (CVE-2021-46939)

    In the Linux kernel, the following vulnerability has been resolved:

    md/raid1: properly indicate failure when ending a failed write request

    This patch addresses a data corruption bug in raid1 arrays using bitmaps.Without this fix, the bitmap bits
    for the failed I/O end up being cleared.

    Since we are in the failure leg of raid1_end_write_request, the requesteither needs to be retried
    (R1BIO_WriteError) or failed (R1BIO_Degraded). (CVE-2021-46950)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: GTDT: Don't corrupt interrupt mappings on watchdow probe failure (CVE-2021-46953)

    In the Linux kernel, the following vulnerability has been resolved:

    openvswitch: fix stack OOB read while fragmenting IPv4 packets (CVE-2021-46955)

    In the Linux kernel, the following vulnerability has been resolved:

    spi: Fix use-after-free with devm_spi_alloc_* (CVE-2021-46959)

    In the Linux kernel, the following vulnerability has been resolved:

    cifs: Return correct error code from smb2_get_enc_key (CVE-2021-46960)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: scan: Fix a memory leak in an error handling path (CVE-2021-46985)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nftables: avoid overflows in nft_hash_buckets() (CVE-2021-46992)

    In the Linux kernel, the following vulnerability has been resolved:

    ARM: 9064/1: hw_breakpoint: Do not directly check the event's overflow_handler hook (CVE-2021-47006)

    In the Linux kernel, the following vulnerability has been resolved:

    net:emac/emac-mac: Fix a use after free in emac_mac_tx_buf_send (CVE-2021-47013)

    In the Linux kernel, the following vulnerability has been resolved:

    bus: qcom: Put child node before return (CVE-2021-47054)

    In the Linux kernel, the following vulnerability has been resolved:

    mtd: require write permissions for locking and badblock ioctls (CVE-2021-47055)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/rxe: Clear all QP fields if creation failed (CVE-2021-47078)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed (CVE-2021-47117)

    In the Linux kernel, the following vulnerability has been resolved:

    pid: take a reference when initializing `cad_pid` (CVE-2021-47118)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/amdgpu: Fix a use-after-free (CVE-2021-47142)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: do not BUG_ON in link_to_fixup_dir (CVE-2021-47145)

    In the Linux kernel, the following vulnerability has been resolved:

    mld: fix panic in mld_newpack() (CVE-2021-47146)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: skb_linearize the head skb when reassembling msgs (CVE-2021-47162)

    In the Linux kernel, the following vulnerability has been resolved:

    NFS: Don't corrupt the value of pg_bytes_written in nfs_do_recoalesce() (CVE-2021-47166)

    In the Linux kernel, the following vulnerability has been resolved:

    NFS: fix an incorrect limit in filelayout_decode_layout() (CVE-2021-47168)

    In the Linux kernel, the following vulnerability has been resolved:

    net: usb: fix memory leak in smsc75xx_bind (CVE-2021-47171)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Fix sysfs leak in alloc_iommu() (CVE-2021-47177)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: synproxy: Fix out of bounds when parsing TCP options (CVE-2021-47245)

    In the Linux kernel, the following vulnerability has been resolved:

    gfs2: Fix use-after-free in gfs2_glock_shrink_scan (CVE-2021-47254)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/memory-failure: make sure wait for page writeback in memory_failure (CVE-2021-47256)

    In the Linux kernel, the following vulnerability has been resolved:

    NFS: Fix use-after-free in nfs4_init_client() (CVE-2021-47259)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Correct the length check which causes memory corruption (CVE-2021-47274)

    In the Linux kernel, the following vulnerability has been resolved:

    drm: Fix use-after-free read in drm_getunique() (CVE-2021-47280)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1685.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-26558.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-0129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3564.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3573.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46906.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46939.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46950.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46953.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46955.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46985.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46992.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47006.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47054.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47055.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47078.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47117.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47118.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47145.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47146.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47162.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47166.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47168.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47171.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47177.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47245.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47254.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47256.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47259.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47274.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47280.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-29650.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32399.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33034.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33624.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3573");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-47254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.238-182.421");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kpatch.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2020-26558", "CVE-2021-0129", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-29650", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33624", "CVE-2021-46906", "CVE-2021-46938", "CVE-2021-46939", "CVE-2021-46950", "CVE-2021-46953", "CVE-2021-46955", "CVE-2021-46959", "CVE-2021-46960", "CVE-2021-46985", "CVE-2021-46992", "CVE-2021-47006", "CVE-2021-47013", "CVE-2021-47054", "CVE-2021-47055", "CVE-2021-47078", "CVE-2021-47117", "CVE-2021-47118", "CVE-2021-47142", "CVE-2021-47145", "CVE-2021-47146", "CVE-2021-47162", "CVE-2021-47166", "CVE-2021-47168", "CVE-2021-47171", "CVE-2021-47177", "CVE-2021-47245", "CVE-2021-47254", "CVE-2021-47256", "CVE-2021-47259", "CVE-2021-47274", "CVE-2021-47280");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2021-1685");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'kernel-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.238-182.421.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-4.14.238-182.421-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-debuginfo-4.14.238-182.421.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-debuginfo-4.14.238-182.421.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
