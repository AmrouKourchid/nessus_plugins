##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0544. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(133787);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2018-1000007",
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122",
    "CVE-2018-1000301"
  );
  script_bugtraq_id(
    103414,
    103415,
    103436,
    104225
  );
  script_xref(name:"RHSA", value:"2020:0544");

  script_name(english:"RHEL 7 : curl (RHSA-2020:0544)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for curl.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0544 advisory.

    The curl packages provide the libcurl library and the curl utility for downloading files from servers
    using various protocols, including HTTP, FTP, and LDAP.

    Security Fix(es):

    * curl: HTTP authentication leak in redirects (CVE-2018-1000007)

    * curl: FTP path trickery leads to NIL byte out of bounds write (CVE-2018-1000120)

    * curl: RTSP RTP buffer over-read (CVE-2018-1000122)

    * curl: Out-of-bounds heap read when missing RTSP headers allows information leak or denial of service
    (CVE-2018-1000301)

    * curl: LDAP NULL pointer dereference (CVE-2018-1000121)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_0544.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6acebac2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1537125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1552628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1552631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1553398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1575536");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL curl package based on the guidance in RHSA-2020:0544.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 200, 476, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcurl-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.5')) audit(AUDIT_OS_NOT, 'Red Hat 7.5', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/eus/rhel/computenode/7/7.5/x86_64/debug',
      'content/eus/rhel/computenode/7/7.5/x86_64/optional/debug',
      'content/eus/rhel/computenode/7/7.5/x86_64/optional/os',
      'content/eus/rhel/computenode/7/7.5/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/7/7.5/x86_64/os',
      'content/eus/rhel/computenode/7/7.5/x86_64/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/highavailability/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/highavailability/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/resilientstorage/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/resilientstorage/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.5/ppc64/debug',
      'content/eus/rhel/power/7/7.5/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.5/ppc64/optional/os',
      'content/eus/rhel/power/7/7.5/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.5/ppc64/os',
      'content/eus/rhel/power/7/7.5/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/debug',
      'content/eus/rhel/server/7/7.5/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.5/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.5/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.5/x86_64/optional/os',
      'content/eus/rhel/server/7/7.5/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/os',
      'content/eus/rhel/server/7/7.5/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/7/7.5/x86_64/resilientstorage/os',
      'content/eus/rhel/server/7/7.5/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.5/s390x/debug',
      'content/eus/rhel/system-z/7/7.5/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.5/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.5/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.5/s390x/os',
      'content/eus/rhel/system-z/7/7.5/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'curl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'curl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'curl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'curl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-devel-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-devel-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-devel-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-devel-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-devel-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-devel-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libcurl-devel-7.29.0-46.el7_5.1', 'sp':'5', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl / libcurl-devel');
}
