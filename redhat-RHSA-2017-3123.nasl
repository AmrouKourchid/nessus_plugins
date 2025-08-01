#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3123. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104457);
  script_version("3.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2017-12629");
  script_xref(name:"RHSA", value:"2017:3123");
  script_xref(name:"IAVA", value:"2021-A-0392-S");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Enterprise Application Platform (RHSA-2017:3123)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat JBoss Enterprise Application Platform.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by a vulnerability as referenced
in the RHSA-2017:3123 advisory.

    Red Hat JBoss Enterprise Application Platform is a platform for Java applications based on the JBoss
    Application Server.

    This asynchronous patch is a security update for lucene package in Red Hat JBoss Enterprise Application
    Platform 7.0.8.

    Security Fix(es):

    * It was found that Apache Lucene would accept an object from an unauthenticated user that could be
    manipulated through subsequent post requests. An attacker could use this flaw to assemble an object that
    could permit execution of arbitrary code if the server enabled Apache Solr's Config API. (CVE-2017-12629)

    For more information regarding CVE-2017-12629, see the article linked in the references section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf165061");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_3123.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd34964b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/CVE-2017-12629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1501529");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:3123");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform package based on the guidance in RHSA-2017:3123.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12629");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(138);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-analyzers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-backward-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-facet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-queries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-queryparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-solr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'eap7-lucene-analyzers-common-5.3.1-4.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-backward-codecs-5.3.1-4.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-core-5.3.1-4.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-facet-5.3.1-4.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-misc-5.3.1-4.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-queries-5.3.1-4.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-queryparser-5.3.1-4.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-solr-5.3.1-4.redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.0/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.0/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.0/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-lucene-analyzers-common-5.3.1-4.redhat_2.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-backward-codecs-5.3.1-4.redhat_2.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-core-5.3.1-4.redhat_2.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-facet-5.3.1-4.redhat_2.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-misc-5.3.1-4.redhat_2.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-queries-5.3.1-4.redhat_2.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-queryparser-5.3.1-4.redhat_2.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-lucene-solr-5.3.1-4.redhat_2.1.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-lucene-analyzers-common / eap7-lucene-backward-codecs / etc');
}
