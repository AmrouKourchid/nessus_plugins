#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0792. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76291);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2014-0248");
  script_bugtraq_id(68174);
  script_xref(name:"RHSA", value:"2014:0792");

  script_name(english:"RHEL 5 / 6 : Red Hat JBoss Enterprise Web Platform 5.2.0 (RHSA-2014:0792)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat JBoss Enterprise Web Platform 5.2.0.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by a vulnerability as referenced
in the RHSA-2014:0792 advisory.

    Red Hat JBoss Enterprise Web Platform is a platform for Java applications,
    which integrates the JBoss Web Server with JBoss Hibernate and JBoss Seam.

    It was found that the org.jboss.seam.web.AuthenticationFilter class
    implementation did not properly use Seam logging. A remote attacker could
    send specially crafted authentication headers to an application, which
    could result in arbitrary code execution with the privileges of the user
    running that application. (CVE-2014-0248)

    The CVE-2014-0248 issue was discovered by Marek Schmidt of Red Hat.

    All users of Red Hat JBoss Enterprise Web Platform 5.2.0 on Red Hat
    Enterprise Linux 4, 5, and 6 are advised to upgrade to these updated
    packages. The JBoss server process must be restarted for the update to take
    effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_0792.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1aac0769");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:0792");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1101619");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Web Platform 5.2.0 package based on the guidance in RHSA-2014:0792.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0248");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5','6'])) audit(AUDIT_OS_NOT, 'Red Hat 5.x / 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/jbewp/5/os',
      'content/dist/rhel/server/5/5Server/i386/jbewp/5/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbewp/5/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbewp/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jboss-seam2-2.2.6.EAP5-12.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-docs-2.2.6.EAP5-12.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-examples-2.2.6.EAP5-12.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-runtime-2.2.6.EAP5-12.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbewp/5/os',
      'content/dist/rhel/server/6/6Server/i386/jbewp/5/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbewp/5/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbewp/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jboss-seam2-2.2.6.EAP5-16.el6_5', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-docs-2.2.6.EAP5-16.el6_5', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-examples-2.2.6.EAP5-16.el6_5', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jboss-seam2-runtime-2.2.6.EAP5-16.el6_5', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jboss-seam2 / jboss-seam2-docs / jboss-seam2-examples / etc');
}
