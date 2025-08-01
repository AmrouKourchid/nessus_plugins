#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:7537. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235930);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/14");

  script_cve_id("CVE-2025-31498");
  script_xref(name:"RHSA", value:"2025:7537");

  script_name(english:"RHEL 9 : nodejs:20 (RHSA-2025:7537)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for nodejs:20.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2025:7537 advisory.

    Node.js is a software development platform for building fast and scalable network applications in the
    JavaScript programming language.

    Security Fix(es):

    * c-ares: c-ares has a use-after-free in read_answers() (CVE-2025-31498)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358271");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_7537.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5486165d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:7537");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL nodejs:20 package based on the guidance in RHSA-2025:7537.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-packaging-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:npm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.4')) audit(AUDIT_OS_NOT, 'Red Hat 9.4', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'nodejs:20': [
    {
      'repo_relative_urls': [
        'content/aus/rhel9/9.4/x86_64/appstream/debug',
        'content/aus/rhel9/9.4/x86_64/appstream/os',
        'content/aus/rhel9/9.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel9/9.4/aarch64/appstream/debug',
        'content/e4s/rhel9/9.4/aarch64/appstream/os',
        'content/e4s/rhel9/9.4/aarch64/appstream/source/SRPMS',
        'content/e4s/rhel9/9.4/ppc64le/appstream/debug',
        'content/e4s/rhel9/9.4/ppc64le/appstream/os',
        'content/e4s/rhel9/9.4/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel9/9.4/s390x/appstream/debug',
        'content/e4s/rhel9/9.4/s390x/appstream/os',
        'content/e4s/rhel9/9.4/s390x/appstream/source/SRPMS',
        'content/e4s/rhel9/9.4/x86_64/appstream/debug',
        'content/e4s/rhel9/9.4/x86_64/appstream/os',
        'content/e4s/rhel9/9.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel9/9.4/aarch64/appstream/debug',
        'content/eus/rhel9/9.4/aarch64/appstream/os',
        'content/eus/rhel9/9.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel9/9.4/ppc64le/appstream/debug',
        'content/eus/rhel9/9.4/ppc64le/appstream/os',
        'content/eus/rhel9/9.4/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel9/9.4/s390x/appstream/debug',
        'content/eus/rhel9/9.4/s390x/appstream/os',
        'content/eus/rhel9/9.4/s390x/appstream/source/SRPMS',
        'content/eus/rhel9/9.4/x86_64/appstream/debug',
        'content/eus/rhel9/9.4/x86_64/appstream/os',
        'content/eus/rhel9/9.4/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'nodejs-20.18.2-2.module+el9.4.0+23089+aaa18a20', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nodejs-devel-20.18.2-2.module+el9.4.0+23089+aaa18a20', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nodejs-docs-20.18.2-2.module+el9.4.0+23089+aaa18a20', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nodejs-full-i18n-20.18.2-2.module+el9.4.0+23089+aaa18a20', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nodejs-nodemon-3.0.1-1.module+el9.3.0.z+20478+84a9f781', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nodejs-packaging-2021.06-4.module+el9.3.0+19518+63aad52d', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'nodejs-packaging-bundler-2021.06-4.module+el9.3.0+19518+63aad52d', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'npm-10.8.2-1.20.18.2.2.module+el9.4.0+23089+aaa18a20', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/nodejs');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:20');
if ('20' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module nodejs:' + module_ver);

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:20');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-devel / nodejs-docs / nodejs-full-i18n / etc');
}
