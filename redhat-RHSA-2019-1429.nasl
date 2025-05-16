#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1429. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193687);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2019-8320",
    "CVE-2019-8321",
    "CVE-2019-8322",
    "CVE-2019-8323",
    "CVE-2019-8324",
    "CVE-2019-8325"
  );
  script_xref(name:"RHSA", value:"2019:1429");

  script_name(english:"RHEL 7 : CloudForms 4.7.5 (RHSA-2019:1429)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:1429 advisory.

    Red Hat CloudForms Management Engine delivers the insight, control, and automation needed to address the
    challenges of managing virtual environments. CloudForms Management Engine is built on Ruby on Rails, a
    model-view-controller (MVC) framework for web application development. Action Pack implements the
    controller and the view components.

    Security Fix(es):

    * rubygems: Installing a malicious gem may lead to arbitrary code execution (CVE-2019-8324)

    * rubygems: Delete directory using symlink when decompressing tar (CVE-2019-8320)

    * rubygems: Escape sequence injection vulnerability in verbose (CVE-2019-8321)

    * rubygems: Escape sequence injection vulnerability in gem owner (CVE-2019-8322)

    * rubygems: Escape sequence injection vulnerability in API response handling (CVE-2019-8323)

    * rubygems: Escape sequence injection vulnerability in errors (CVE-2019-8325)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    This update fixes various bugs and adds enhancements. Documentation for these changes is available from
    the Release Notes document linked to in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  # https://access.redhat.com/documentation/en-us/red_hat_cloudforms/4.7/html/release_notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5668a5e0");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1669023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1692512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1692514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1692516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1692519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1692520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1692522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1703104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1710497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1710578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1710606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1710608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1710610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1710998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1712135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1712440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1712595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1713477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1713731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1713732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1717500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1717501");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_1429.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5c60567");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1429");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8320");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-8324");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 88);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme-amazon-smartstate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme-appliance-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme-appliance-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme-gemset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/cf-me/server/5.10/x86_64/debug',
      'content/dist/cf-me/server/5.10/x86_64/os',
      'content/dist/cf-me/server/5.10/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cfme-5.10.5.1-1.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'cfme-amazon-smartstate-5.10.5.1-1.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'cfme-appliance-5.10.5.1-1.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'cfme-appliance-common-5.10.5.1-1.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'cfme-appliance-tools-5.10.5.1-1.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'cfme-gemset-5.10.5.1-1.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'ruby-2.4.6-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'ruby-devel-2.4.6-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'ruby-doc-2.4.6-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'ruby-irb-2.4.6-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'ruby-libs-2.4.6-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-bigdecimal-1.3.2-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-did_you_mean-1.1.0-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-io-console-0.4.6-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-minitest-5.10.1-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-net-telnet-0.1.1-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-openssl-2.0.9-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-power_assert-0.4.1-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-psych-2.2.2-91.el7cf', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-rake-12.0.0-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-rdoc-5.0.0-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-test-unit-3.2.3-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygem-xmlrpc-0.2.1-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygems-2.6.14.4-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'},
      {'reference':'rubygems-devel-2.6.14.4-91.el7cf', 'release':'7', 'el_string':'el7cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.10'}
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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cfme / cfme-amazon-smartstate / cfme-appliance / etc');
}
