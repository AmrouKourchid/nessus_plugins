#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0173. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(112174);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2016-7061", "CVE-2016-8627");
  script_xref(name:"RHSA", value:"2017:0173");

  script_name(english:"RHEL 6 / 7 : eap7-jboss-ec2-eap (RHSA-2017:0173)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for eap7-jboss-ec2-eap.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:0173 advisory.

    The eap7-jboss-ec2-eap package provides scripts for Red Hat JBoss Enterprise Application Platform running
    on the Amazon Web Services (AWS) Elastic Compute Cloud (EC2).

    With this update, the eap7-jboss-ec2-eap package has been updated to ensure compatibility with Red Hat
    JBoss Enterprise Application Platform 7.0.4.

    Refer to the JBoss Enterprise Application Platform 7.0.4 Release Notes, linked to in the References
    section, for information on the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * An EAP feature to download server log files allows logs to be available via GET requests making them
    vulnerable to cross-origin attacks. An attacker could trigger the user's browser to request the log files
    consuming enough resources that normal server functioning could be impaired. (CVE-2016-8627)

    * It was discovered that when configuring RBAC and marking information as sensitive, users with a Monitor
    role are able to view the sensitive information. (CVE-2016-7061)

    The CVE-2016-8627 issue was discovered by Darran Lofthouse and Brian Stansberry (Red Hat).

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_0173.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df826786");
  # https://access.redhat.com/documentation/en/jboss-enterprise-application-platform/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e41b214b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:0173");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1380852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1388240");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-5962");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL eap7-jboss-ec2-eap package based on the guidance in RHSA-2017:0173.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7061");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ec2-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ec2-eap-samples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-jboss-ec2-eap-7.0.4-5.GA_redhat_2.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-ec2-eap-samples-7.0.4-5.GA_redhat_2.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.0/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.0/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.0/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-jboss-ec2-eap-7.0.4-5.GA_redhat_2.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-ec2-eap-samples-7.0.4-5.GA_redhat_2.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-jboss-ec2-eap / eap7-jboss-ec2-eap-samples');
}
