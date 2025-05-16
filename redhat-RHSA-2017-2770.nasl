#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2770. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103351);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2017-7533");
  script_xref(name:"RHSA", value:"2017:2770");

  script_name(english:"RHEL 7 : kernel (RHSA-2017:2770)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2017:2770 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * A race condition was found in the Linux kernel, present since v3.14-rc1 through v4.12. The race happens
    between threads of inotify_handle_event() and vfs_rename() while running the rename operation against the
    same file. As a result of the race the next slab data or the slab's free list pointer can be corrupted
    with attacker-controlled data, which may lead to the privilege escalation. (CVE-2017-7533, Important)

    Red Hat would like to thank Leilei Lin (Alibaba Group), Fan Wu (The University of Hong Kong), and Shixiong
    Zhao (The University of Hong Kong) for reporting this issue.

    Bug Fix(es):

    * Previously, the sha1-avx2 optimized hashing, which is used on processors supporting avx2, under certain
    conditions miscalculated an offset. Consequently, a kernel crash occasionally occurred on the NFS clients
    or servers using the krb5 security. With this update, the optimized hashing path for sha1-avx2 has been
    disabled, and the NFS clients and servers with krb5 security no longer experience the miscalculation and
    subsequent crash. (BZ#1446230)

    * When virt boundary limit was set, lots of small bios could not be merged even though they were
    contiguous physically. In some workload, such as mkfs.ntfs, system performance could be ten times
    degraded. The proposed patch fixes the bug by allowing to merge these small bios, which improves
    performance of mkfs.ntfs on devices significantly. (BZ#1472674)

    * When executing the mkfs.btrfs command to create a btrfs file system over Non-Volatile Memory Express
    (NVMe), kernel panic was previously triggered. The underlying code has been patched to fix this
    regression, and btrfs is now created successfully in the described scenario. (BZ#1472675)

    * As a side effect of BZ#147263, the system previously crashed when creating a container device. The
    provided patch transforms the resched_task() function into resched_curr(), and the chance of kernel crash
    is thus reduced in the aforementioned situation. (BZ#1473742)

    * Due to incorrectly used memory in VXLAN driver (a use-after-free bug and list corruption), the kernel
    could previously panic under some circumstances while bringing the VXLAN interfaces down. The provided
    patch fixes the memory corruptions, and the panic no longer occurs in this situation. (BZ#1474263)

    * A race condition could cause the in-flight asynchronous buffers count (bt_io_count) to become negative.
    This caused the umount operation to hang in the xfs_wait_buftarg() function. The provided patch fixes the
    buffer I/O accounting release race, and XFS umount no longer hangs. (BZ#1478253)

    * Kernel version 3.10.0-498.el7 separated CPU and TSC frequency and introduced the
    x86_platform.calibrate_cpu function pointer which points by default to the native_calibrate_cpu()
    function. As a consequence, time synchronization bugs appeared on Red Hat Enterprise Linux 7.3 ESXi guest
    causing a time offset shortly after boot. An upstream patch has been applied, which sets
    x86_platform.calibrate_cpu pointer on ESXi guests to the proper function, thus fixing this bug.
    (BZ#1479245)

    * A system having more than 128 CPUs could previously experience a crash during shutdown after the
    Intelligent Platform Management Interface (IPMI) service was stopped. The provided patch fixes a race
    condition in the IPMI smi_timeout() function, allowing the system to shut down as expected. (BZ#1479760)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_2770.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f476aeba");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2770");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1468283");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2017:2770.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7533");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(642);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.3')) audit(AUDIT_OS_NOT, 'Red Hat 7.3', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2017-7533');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2017:2770');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/7/7.3/x86_64/debug',
      'content/aus/rhel/server/7/7.3/x86_64/optional/debug',
      'content/aus/rhel/server/7/7.3/x86_64/optional/os',
      'content/aus/rhel/server/7/7.3/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/7/7.3/x86_64/os',
      'content/aus/rhel/server/7/7.3/x86_64/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.3/ppc64le/debug',
      'content/e4s/rhel/power-le/7/7.3/ppc64le/optional/debug',
      'content/e4s/rhel/power-le/7/7.3/ppc64le/optional/os',
      'content/e4s/rhel/power-le/7/7.3/ppc64le/optional/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.3/ppc64le/os',
      'content/e4s/rhel/power-le/7/7.3/ppc64le/source/SRPMS',
      'content/e4s/rhel/server/7/7.3/x86_64/debug',
      'content/e4s/rhel/server/7/7.3/x86_64/highavailability/debug',
      'content/e4s/rhel/server/7/7.3/x86_64/highavailability/os',
      'content/e4s/rhel/server/7/7.3/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel/server/7/7.3/x86_64/optional/debug',
      'content/e4s/rhel/server/7/7.3/x86_64/optional/os',
      'content/e4s/rhel/server/7/7.3/x86_64/optional/source/SRPMS',
      'content/e4s/rhel/server/7/7.3/x86_64/os',
      'content/e4s/rhel/server/7/7.3/x86_64/source/SRPMS',
      'content/eus/rhel/computenode/7/7.3/x86_64/debug',
      'content/eus/rhel/computenode/7/7.3/x86_64/optional/debug',
      'content/eus/rhel/computenode/7/7.3/x86_64/optional/os',
      'content/eus/rhel/computenode/7/7.3/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/7/7.3/x86_64/os',
      'content/eus/rhel/computenode/7/7.3/x86_64/source/SRPMS',
      'content/eus/rhel/power-le/7/7.3/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.3/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.3/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.3/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.3/ppc64le/os',
      'content/eus/rhel/power-le/7/7.3/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.3/ppc64/debug',
      'content/eus/rhel/power/7/7.3/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.3/ppc64/optional/os',
      'content/eus/rhel/power/7/7.3/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.3/ppc64/os',
      'content/eus/rhel/power/7/7.3/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.3/x86_64/debug',
      'content/eus/rhel/server/7/7.3/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.3/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.3/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.3/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.3/x86_64/optional/os',
      'content/eus/rhel/server/7/7.3/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.3/x86_64/os',
      'content/eus/rhel/server/7/7.3/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.3/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.3/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.3/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.3/s390x/debug',
      'content/eus/rhel/system-z/7/7.3/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.3/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.3/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.3/s390x/os',
      'content/eus/rhel/system-z/7/7.3/s390x/source/SRPMS',
      'content/tus/rhel/server/7/7.3/x86_64/debug',
      'content/tus/rhel/server/7/7.3/x86_64/optional/debug',
      'content/tus/rhel/server/7/7.3/x86_64/optional/os',
      'content/tus/rhel/server/7/7.3/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/7/7.3/x86_64/os',
      'content/tus/rhel/server/7/7.3/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-514.32.2.el7', 'sp':'3', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-bootwrapper / kernel-debug / kernel-debug-devel / etc');
}
