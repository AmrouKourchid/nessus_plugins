#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:5259. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205433);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2022-1011", "CVE-2024-36971");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");
  script_xref(name:"RHSA", value:"2024:5259");

  script_name(english:"RHEL 7 : kernel (RHSA-2024:5259)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:5259 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating
    system.

    Security Fix(es):

    * kernel: FUSE allows UAF reads of write() buffers, allowing theft of (partial) /etc/shadow hashes
    (CVE-2022-1011)

    * net: fix __dst_negative_advice() race (CVE-2024-36971)

    Bug Fix(es):

    * kernel.spec: run initramfs generation in %post (not only in %posttrans)
    (RHEL-3292)

    * tcp: fix zero cwnd in tcp_cwnd_reduction (RHEL-43212)

    * epoll: fix use-after-free in eventpoll_release_file (RHEL-39665)

    * RHEL 7.9: include  [net] netfilter: ipset: fix ip_set_list allocation failure (RHEL-6204)

    * gfs2: The gfs2_logd process to hang or stall which causes a performance degradation on the gfs2
    filesystem (RHEL-8427)

    * [rhel7] gfs2: quota_change%u corruption (RHEL-37473)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2064855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292331");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_5259.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19357be8");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:5259");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2024:5259.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1011");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-36971");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(416);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_els:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-1011', 'CVE-2024-36971');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:5259');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/els/rhel/power-le/7/7Server/ppc64le/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/els/rhel/power/7/7Server/ppc64/debug',
      'content/els/rhel/power/7/7Server/ppc64/optional/debug',
      'content/els/rhel/power/7/7Server/ppc64/optional/os',
      'content/els/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/els/rhel/power/7/7Server/ppc64/os',
      'content/els/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/debug',
      'content/els/rhel/server/7/7Server/x86_64/optional/debug',
      'content/els/rhel/server/7/7Server/x86_64/optional/os',
      'content/els/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/os',
      'content/els/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/els/rhel/system-z/7/7Server/s390x/debug',
      'content/els/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/els/rhel/system-z/7/7Server/s390x/optional/os',
      'content/els/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/els/rhel/system-z/7/7Server/s390x/os',
      'content/els/rhel/system-z/7/7Server/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bpftool-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1160.123.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1160.123.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1160.123.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-3.10.0-1160.123.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-bootwrapper / kernel-debug / etc');
}
