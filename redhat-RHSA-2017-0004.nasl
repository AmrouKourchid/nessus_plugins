#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0004. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(96307);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2016-8666");
  script_xref(name:"RHSA", value:"2017:0004");

  script_name(english:"RHEL 7 : kernel (RHSA-2017:0004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2017:0004 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * A flaw was found in the way the Linux kernel's networking subsystem handled offloaded packets with
    multiple layers of encapsulation in the GRO (Generic Receive Offload) code path. A remote attacker could
    use this flaw to trigger unbounded recursion in the kernel that could lead to stack corruption, resulting
    in a system crash. (CVE-2016-8666, Important)

    Bug Fix(es):

    * When a virtual machine (VM) with PCI-Passthrough interfaces was recreated, the operating system
    rebooted. This update fixes the race condition between the eventfd daemon and the virqfd daemon. As a
    result, the operating system no longer reboots in the described situation. (BZ#1391609)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_0004.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f54713f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:0004");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1384991");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2017:0004.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8666");
  script_cwe_id(674);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.1')) audit(AUDIT_OS_NOT, 'Red Hat 7.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2016-8666');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2017:0004');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/eus/rhel/computenode/7/7.1/x86_64/debug',
      'content/eus/rhel/computenode/7/7.1/x86_64/optional/debug',
      'content/eus/rhel/computenode/7/7.1/x86_64/optional/os',
      'content/eus/rhel/computenode/7/7.1/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/7/7.1/x86_64/os',
      'content/eus/rhel/computenode/7/7.1/x86_64/source/SRPMS',
      'content/eus/rhel/power-le/7/7.1/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.1/ppc64le/os',
      'content/eus/rhel/power-le/7/7.1/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.1/ppc64/debug',
      'content/eus/rhel/power/7/7.1/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.1/ppc64/optional/os',
      'content/eus/rhel/power/7/7.1/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.1/ppc64/os',
      'content/eus/rhel/power/7/7.1/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/debug',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.1/x86_64/optional/os',
      'content/eus/rhel/server/7/7.1/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/os',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.1/s390x/debug',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.1/s390x/os',
      'content/eus/rhel/system-z/7/7.1/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-229.46.1.el7', 'sp':'1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/eus/rhel/power-le/7/7.1/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.1/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.1/ppc64le/os',
      'content/eus/rhel/power-le/7/7.1/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.1/ppc64/debug',
      'content/eus/rhel/power/7/7.1/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.1/ppc64/optional/os',
      'content/eus/rhel/power/7/7.1/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.1/ppc64/os',
      'content/eus/rhel/power/7/7.1/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/debug',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.1/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.1/x86_64/optional/os',
      'content/eus/rhel/server/7/7.1/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/os',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.1/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.1/s390x/debug',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.1/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.1/s390x/os',
      'content/eus/rhel/system-z/7/7.1/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-229.46.1.ael7b', 'sp':'1', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
