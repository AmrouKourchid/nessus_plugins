#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.10-2023-025.
##

include('compat.inc');

if (description)
{
  script_id(170472);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/17");

  script_cve_id(
    "CVE-2022-3435",
    "CVE-2022-3623",
    "CVE-2022-3643",
    "CVE-2022-4378",
    "CVE-2022-48946",
    "CVE-2022-48949",
    "CVE-2022-48956",
    "CVE-2022-48969",
    "CVE-2022-48970",
    "CVE-2022-48972",
    "CVE-2022-48977",
    "CVE-2022-48978",
    "CVE-2022-48981",
    "CVE-2022-48986",
    "CVE-2022-48987",
    "CVE-2022-48988",
    "CVE-2022-48991",
    "CVE-2022-48997",
    "CVE-2022-48999",
    "CVE-2022-49000",
    "CVE-2022-49002",
    "CVE-2022-49006",
    "CVE-2022-49007",
    "CVE-2022-49013",
    "CVE-2022-49014",
    "CVE-2022-49015",
    "CVE-2022-49017",
    "CVE-2022-49021",
    "CVE-2022-49025",
    "CVE-2022-49027",
    "CVE-2022-49028",
    "CVE-2022-49030",
    "CVE-2022-49033",
    "CVE-2022-42328",
    "CVE-2022-42329",
    "CVE-2023-1295",
    "CVE-2023-2166"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.10-2023-025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.10.162-141.675. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.10-2023-025 advisory.

    A vulnerability classified as problematic has been found in Linux Kernel. This affects the function
    fib_nh_match of the file net/ipv4/fib_semantics.c of the component IPv4 Handler. The manipulation leads to
    out-of-bounds read. It is possible to initiate the attack remotely. It is recommended to apply a patch to
    fix this issue. The identifier VDB-210357 was assigned to this vulnerability. (CVE-2022-3435)

    A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function follow_page_pte of the file mm/gup.c of the component BPF. The manipulation
    leads to race condition. The attack can be launched remotely. It is recommended to apply a patch to fix
    this issue. The identifier VDB-211921 was assigned to this vulnerability. (CVE-2022-3623)

    Guests can trigger NIC interface reset/abort/crash via netback It is possible for a guest to trigger a NIC
    interface reset/abort/crash in a Linux based network backend by sending certain kinds of packets. It
    appears to be an (unwritten?) assumption in the rest of the Linux network stack that packet protocol
    headers are all contained within the linear section of the SKB and some NICs behave badly if this is not
    the case. This has been reported to occur with Cisco (enic) and Broadcom NetXtrem II BCM5780 (bnx2x)
    though it may be an issue with other NICs/drivers as well. In case the frontend is sending requests with
    split headers, netback will forward those violating above mentioned assumption to the networking core,
    resulting in said misbehavior. (CVE-2022-3643)

    Guests can trigger deadlock in Linux netback driver T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] The patch for XSA-392 introduced
    another issue which might result in a deadlock when trying to free the SKB of a packet dropped due to the
    XSA-392 handling (CVE-2022-42328). Additionally when dropping packages for other reasons the same deadlock
    could occur in case of netpoll being active for the interface the xen-netback driver is connected to
    (CVE-2022-42329). (CVE-2022-42328)

    Guests can trigger deadlock in Linux netback driver T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] The patch for XSA-392 introduced
    another issue which might result in a deadlock when trying to free the SKB of a packet dropped due to the
    XSA-392 handling (CVE-2022-42328). Additionally when dropping packages for other reasons the same deadlock
    could occur in case of netpoll being active for the interface the xen-netback driver is connected to
    (CVE-2022-42329). (CVE-2022-42329)

    A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in how a user changes certain
    kernel parameters and variables. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2022-4378)

    In the Linux kernel, the following vulnerability has been resolved:

    udf: Fix preallocation discarding at indirect extent boundary (CVE-2022-48946)

    In the Linux kernel, the following vulnerability has been resolved:

    igb: Initialize mailbox message for VF reset (CVE-2022-48949)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: avoid use-after-free in ip6_fragment() (CVE-2022-48956)

    In the Linux kernel, the following vulnerability has been resolved:

    xen-netfront: Fix NULL sring after live migration (CVE-2022-48969)

    In the Linux kernel, the following vulnerability has been resolved:

    af_unix: Get user_ns from in_skb in unix_diag_get_exact(). (CVE-2022-48970)

    In the Linux kernel, the following vulnerability has been resolved:

    mac802154: fix missing INIT_LIST_HEAD in ieee802154_if_add() (CVE-2022-48972)

    In the Linux kernel, the following vulnerability has been resolved:

    can: af_can: fix NULL pointer dereference in can_rcv_filter (CVE-2022-48977)

    In the Linux kernel, the following vulnerability has been resolved:

    HID: core: fix shift-out-of-bounds in hid_report_raw_event (CVE-2022-48978)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/shmem-helper: Remove errant put in error path (CVE-2022-48981)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/gup: fix gup_pud_range() for dax (CVE-2022-48986)

    In the Linux kernel, the following vulnerability has been resolved:

    media: v4l2-dv-timings.c: fix too strict blanking sanity checks (CVE-2022-48987)

    In the Linux kernel, the following vulnerability has been resolved:

    memcg: fix possible use-after-free in memcg_write_event_control() (CVE-2022-48988)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/khugepaged: invoke MMU notifiers in shmem/file collapse paths (CVE-2022-48991)

    In the Linux kernel, the following vulnerability has been resolved:

    char: tpm: Protect tpm_pm_suspend with locks (CVE-2022-48997)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv4: Handle attempt to delete multipath route when fib_info contains an nh reference (CVE-2022-48999)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Fix PCI device refcount leak in has_external_pci() (CVE-2022-49000)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Fix PCI device refcount leak in dmar_dev_scope_init() (CVE-2022-49002)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Free buffers when a used dynamic event is removed (CVE-2022-49006)

    In the Linux kernel, the following vulnerability has been resolved:

    nilfs2: fix NULL pointer dereference in nilfs_palloc_commit_free_entry() (CVE-2022-49007)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: fix memory leak in sctp_stream_outq_migrate() (CVE-2022-49013)

    In the Linux kernel, the following vulnerability has been resolved:

    net: tun: Fix use-after-free in tun_detach() (CVE-2022-49014)

    In the Linux kernel, the following vulnerability has been resolved:

    net: hsr: Fix potential use-after-free (CVE-2022-49015)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: re-fetch skb cb after tipc_msg_validate (CVE-2022-49017)

    In the Linux kernel, the following vulnerability has been resolved:

    net: phy: fix null-ptr-deref while probe() failed (CVE-2022-49021)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: Fix use-after-free when reverting termination table (CVE-2022-49025)

    In the Linux kernel, the following vulnerability has been resolved:

    iavf: Fix error handling in iavf_init_module() (CVE-2022-49027)

    In the Linux kernel, the following vulnerability has been resolved:

    ixgbevf: Fix resource leak in ixgbevf_init_module() (CVE-2022-49028)

    In the Linux kernel, the following vulnerability has been resolved:

    libbpf: Handle size overflow for ringbuf mmap (CVE-2022-49030)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: qgroup: fix sleep from invalid context bug in btrfs_qgroup_inherit() (CVE-2022-49033)

    A time-of-check to time-of-use issue exists in io_uring subsystem's IORING_OP_CLOSE operation in the Linux
    kernel's versions 5.6 - 5.11 (inclusive), which allows a local user to elevate their privileges to root.
    Introduced in b5dba59e0cf7e2cc4d3b3b1ac5fe81ddf21959eb, patched in
    9eac1904d3364254d622bf2c771c4f85cd435fc2, backported to stable in
    788d0824269bef539fe31a785b1517882eafed93. (CVE-2023-1295)

    A null pointer dereference issue was found in the can protocol in net/can/af_can.c in the Linux Kernel.
    ml_priv may not be initialized in the receive path of CAN frames. This issue could allow a local user to
    crash the system or cause a denial of service. (CVE-2023-2166)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2023-025.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3435.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3643.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4378.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48946.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48949.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48956.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48969.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48970.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48972.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48977.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48978.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48981.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48986.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48987.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48988.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48991.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48997.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48999.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49000.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49002.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49006.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49007.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49014.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49015.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49017.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49021.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49025.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49027.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49028.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49030.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-49033.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42328.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42329.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1295.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-2166.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3623");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-49030");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.10.162-141.675");
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

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "kpatch.nasl");
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
  var cve_list = make_list("CVE-2022-3435", "CVE-2022-3623", "CVE-2022-3643", "CVE-2022-4378", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-48946", "CVE-2022-48949", "CVE-2022-48956", "CVE-2022-48969", "CVE-2022-48970", "CVE-2022-48972", "CVE-2022-48977", "CVE-2022-48978", "CVE-2022-48981", "CVE-2022-48986", "CVE-2022-48987", "CVE-2022-48988", "CVE-2022-48991", "CVE-2022-48997", "CVE-2022-48999", "CVE-2022-49000", "CVE-2022-49002", "CVE-2022-49006", "CVE-2022-49007", "CVE-2022-49013", "CVE-2022-49014", "CVE-2022-49015", "CVE-2022-49017", "CVE-2022-49021", "CVE-2022-49025", "CVE-2022-49027", "CVE-2022-49028", "CVE-2022-49030", "CVE-2022-49033", "CVE-2023-1295", "CVE-2023-2166");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.10-2023-025");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.10"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-aarch64-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-x86_64-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.162-141.675.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.162-141.675-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.162-141.675-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.162-141.675.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.162-141.675.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'}
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
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
