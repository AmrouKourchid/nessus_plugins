##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:2214. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161084);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2018-25032");
  script_xref(name:"RHSA", value:"2022:2214");

  script_name(english:"RHEL 6 : zlib (RHSA-2022:2214)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for zlib.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2022:2214 advisory.

    The zlib packages provide a general-purpose lossless data compression library that is used by many
    different programs.

    Security Fix(es):

    * zlib: A flaw found in zlib when compressing (not decompressing) certain inputs (CVE-2018-25032)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_2214.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355e3551");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:2214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2067945");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL zlib package based on the guidance in RHSA-2022:2214.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-25032");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_els:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:minizip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:minizip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:zlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:zlib-static");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/els/rhel/server/6/6Server/i386/debug',
      'content/els/rhel/server/6/6Server/i386/extended-optional/debug',
      'content/els/rhel/server/6/6Server/i386/extended-optional/os',
      'content/els/rhel/server/6/6Server/i386/extended-optional/source/SRPMS',
      'content/els/rhel/server/6/6Server/i386/extended/debug',
      'content/els/rhel/server/6/6Server/i386/extended/os',
      'content/els/rhel/server/6/6Server/i386/extended/source/SRPMS',
      'content/els/rhel/server/6/6Server/i386/optional/debug',
      'content/els/rhel/server/6/6Server/i386/optional/os',
      'content/els/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/els/rhel/server/6/6Server/i386/os',
      'content/els/rhel/server/6/6Server/i386/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/debug',
      'content/els/rhel/server/6/6Server/x86_64/extended-optional/debug',
      'content/els/rhel/server/6/6Server/x86_64/extended-optional/os',
      'content/els/rhel/server/6/6Server/x86_64/extended-optional/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/extended/debug',
      'content/els/rhel/server/6/6Server/x86_64/extended/os',
      'content/els/rhel/server/6/6Server/x86_64/extended/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/optional/debug',
      'content/els/rhel/server/6/6Server/x86_64/optional/os',
      'content/els/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/os',
      'content/els/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/els/rhel/system-z/6/6Server/s390x/debug',
      'content/els/rhel/system-z/6/6Server/s390x/extended-optional/debug',
      'content/els/rhel/system-z/6/6Server/s390x/extended-optional/os',
      'content/els/rhel/system-z/6/6Server/s390x/extended-optional/source/SRPMS',
      'content/els/rhel/system-z/6/6Server/s390x/extended/debug',
      'content/els/rhel/system-z/6/6Server/s390x/extended/os',
      'content/els/rhel/system-z/6/6Server/s390x/extended/source/SRPMS',
      'content/els/rhel/system-z/6/6Server/s390x/optional/debug',
      'content/els/rhel/system-z/6/6Server/s390x/optional/os',
      'content/els/rhel/system-z/6/6Server/s390x/optional/source/SRPMS',
      'content/els/rhel/system-z/6/6Server/s390x/os',
      'content/els/rhel/system-z/6/6Server/s390x/source/SRPMS',
      'content/retired-els/rhel/server/6/6Server/x86_64/debug',
      'content/retired-els/rhel/server/6/6Server/x86_64/optional/debug',
      'content/retired-els/rhel/server/6/6Server/x86_64/optional/os',
      'content/retired-els/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/retired-els/rhel/server/6/6Server/x86_64/os',
      'content/retired-els/rhel/server/6/6Server/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'minizip-1.2.3-31.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'minizip-1.2.3-31.el6_10', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'minizip-1.2.3-31.el6_10', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'minizip-1.2.3-31.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'minizip-devel-1.2.3-31.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'minizip-devel-1.2.3-31.el6_10', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'minizip-devel-1.2.3-31.el6_10', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'minizip-devel-1.2.3-31.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-1.2.3-31.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-1.2.3-31.el6_10', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-1.2.3-31.el6_10', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-1.2.3-31.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-devel-1.2.3-31.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-devel-1.2.3-31.el6_10', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-devel-1.2.3-31.el6_10', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-devel-1.2.3-31.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-static-1.2.3-31.el6_10', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-static-1.2.3-31.el6_10', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'zlib-static-1.2.3-31.el6_10', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'minizip / minizip-devel / zlib / zlib-devel / zlib-static');
}
