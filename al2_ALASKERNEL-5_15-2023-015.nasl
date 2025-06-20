#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.15-2023-015.
##

include('compat.inc');

if (description)
{
  script_id(173235);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/07");

  script_cve_id(
    "CVE-2022-2196",
    "CVE-2022-27672",
    "CVE-2023-0458",
    "CVE-2023-1076",
    "CVE-2023-1077",
    "CVE-2023-1078",
    "CVE-2023-1281",
    "CVE-2023-1829",
    "CVE-2023-1872",
    "CVE-2023-1998",
    "CVE-2023-26545",
    "CVE-2023-2985",
    "CVE-2023-45863",
    "CVE-2023-52646",
    "CVE-2023-52702",
    "CVE-2023-52707",
    "CVE-2023-52735",
    "CVE-2023-52739",
    "CVE-2023-52741",
    "CVE-2023-52746",
    "CVE-2023-7192"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.15-2023-015)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.15.102-61.139. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.15-2023-015 advisory.

    2024-12-05: CVE-2023-52739 was added to this advisory.

    2024-12-05: CVE-2023-52702 was added to this advisory.

    2024-11-08: CVE-2023-52741 was added to this advisory.

    2024-11-08: CVE-2023-52735 was added to this advisory.

    2024-08-01: CVE-2023-52646 was added to this advisory.

    2024-07-18: CVE-2023-1872 was added to this advisory.

    2024-07-03: CVE-2023-1076 was added to this advisory.

    2024-06-19: CVE-2023-52707 was added to this advisory.

    2024-06-19: CVE-2023-52746 was added to this advisory.

    2024-01-19: CVE-2023-7192 was added to this advisory.

    2023-10-31: CVE-2023-45863 was added to this advisory.

    2023-08-31: CVE-2023-2985 was added to this advisory.

    A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks.
    L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after
    running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can
    execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past
    commit 2e7eab81425a (CVE-2022-2196)

    It has been discovered that on some AMD CPUs, the RAS (Return Address Stack, also called RAP - Return
    Address Predictor - in some AMD documentation, and RSB - Return Stack Buffer - in Intel terminology) is
    dynamically partitioned between non-idle threads.  This allows an attacker to control speculative
    execution on the adjacent thread. (CVE-2022-27672)

    Detected a few exploitable gadgets that could leak secret memory through a side-channel such as MDS as
    well as insufficient hardening of the usercopy functions against spectre-v1. (CVE-2023-0458)

    Due to a type confusion during initializations, the tun and tap sockets in the Linux Kernel have their
    socket UID hardcoded to 0, i.e. root. While it will be often correct, as TUN/TAP devices require
    CAP_NET_ADMIN, it may not always be the case. The socket UID may be used for network filtering and
    routing, thus TUN/TAP sockets may be incorrectly managed, potentially bypassing network filters based on
    UID. (CVE-2023-1076)

    kernel: Type confusion in pick_next_rt_entity(), which can result in memory corruption. (CVE-2023-1077)

    The upstream bug report describes this issue as follows:

    A flaw found in the Linux Kernel in RDS (Reliable Datagram Sockets) protocol. The
    rds_rm_zerocopy_callback() uses list_entry() on the head of a list causing a type confusion. Local user
    can trigger this with rds_message_put(). Type confusion leads to `struct rds_msg_zcopy_info *info`
    actually points to something else that is potentially controlled by local user. It is known how to trigger
    this, which causes an OOB access, and a lock corruption. (CVE-2023-1078)

    Use After Free vulnerability in Linux kernel traffic control index filter (tcindex) allows Privilege
    Escalation. The imperfect hash area can be updated while packets are traversing, which will cause a use-
    after-free when 'tcf_exts_exec()' is called with the destroyed tcf_ext. A local attacker user can use this
    vulnerability to elevate its privileges to root.This issue affects Linux Kernel: from 4.14 before git
    commit ee059170b1f7e94e55fa6cadee544e176a6e59c2. (CVE-2023-1281)

    A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited
    to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate
    filters in case of a perfect hashes while deleting the underlying structure which can later lead to double
    freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to
    root.We recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28. (CVE-2023-1829)

    A use-after-free vulnerability in the Linux Kernel io_uring system can be exploited to achieve local
    privilege escalation.

    The io_file_get_fixed function lacks the presence of ctx->uring_lock which can lead to a Use-After-Free
    vulnerability due a race condition with fixed files getting unregistered.

    We recommend upgrading past commit da24142b1ef9fd5d36b76e36bab328a5b27523e8. (CVE-2023-1872)

    When plain IBRS is enabled (not enhanced IBRS), the logic in spectre_v2_user_select_mitigation()
    determines that STIBP is not needed. The IBRS bit implicitly protects against cross-thread branch
    targetinjection. However, with legacy IBRS, the IBRS bit is cleared on returning to userspace for
    performance reasons which leaves userspace threads vulnerable to cross-thread branch target injection
    against which STIBP protects. (CVE-2023-1998)

    In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

    A use-after-free flaw was found in hfsplus_put_super in fs/hfsplus/super.c in the Linux Kernel. This flaw
    could allow a local user to cause a denial of service. (CVE-2023-2985)

    An issue was discovered in lib/kobject.c in the Linux kernel before 6.2.3. With root access, an attacker
    can trigger a race condition that results in a fill_kobj_path out-of-bounds write. (CVE-2023-45863)

    In the Linux kernel, the following vulnerability has been resolved:

    aio: fix mremap after fork null-deref (CVE-2023-52646)

    In the Linux kernel, the following vulnerability has been resolved:

    net: openvswitch: fix possible memory leak in ovs_meter_cmd_set() (CVE-2023-52702)

    In the Linux kernel, the following vulnerability has been resolved:

    sched/psi: Fix use-after-free in ep_remove_wait_queue() (CVE-2023-52707)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf, sockmap: Don't let sock_map_{close,destroy,unhash} call itself (CVE-2023-52735)

    In the Linux kernel, the following vulnerability has been resolved:

    Fix page corruption caused by racy check in __free_pages (CVE-2023-52739)

    In the Linux kernel, the following vulnerability has been resolved:

    cifs: Fix use-after-free in rdata->read_into_pages() (CVE-2023-52741)

    In the Linux kernel, the following vulnerability has been resolved:

    xfrm/compat: prevent potential spectre v1 gadget in xfrm_xlate32_attr() (CVE-2023-52746)

    kernel: refcount leak in ctnetlink_create_conntrack() (CVE-2023-7192)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.15-2023-015.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2196.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27672.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0458.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1076.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1077.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1078.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1281.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1829.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1872.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1998.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-26545.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-2985.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-45863.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52646.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52702.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52707.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52735.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52739.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52741.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52746.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-7192.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52741");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.15.102-61.139");
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
  var cve_list = make_list("CVE-2022-2196", "CVE-2022-27672", "CVE-2023-0458", "CVE-2023-1076", "CVE-2023-1077", "CVE-2023-1078", "CVE-2023-1281", "CVE-2023-1829", "CVE-2023-1872", "CVE-2023-1998", "CVE-2023-2985", "CVE-2023-7192", "CVE-2023-26545", "CVE-2023-45863", "CVE-2023-52646", "CVE-2023-52702", "CVE-2023-52707", "CVE-2023-52735", "CVE-2023-52739", "CVE-2023-52741", "CVE-2023-52746");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.15-2023-015");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.15"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'bpftool-debuginfo-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-aarch64-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-debuginfo-common-x86_64-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-devel-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.102-61.139.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-headers-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.102-61.139-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-livepatch-5.15.102-61.139-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-debuginfo-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'kernel-tools-devel-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'perf-debuginfo-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.102-61.139.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'},
    {'reference':'python-perf-debuginfo-5.15.102-61.139.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.15'}
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
      severity   : SECURITY_WARNING,
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
