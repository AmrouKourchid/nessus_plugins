#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1430. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92400);
  script_version("2.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2015-4734",
    "CVE-2015-4803",
    "CVE-2015-4805",
    "CVE-2015-4806",
    "CVE-2015-4810",
    "CVE-2015-4835",
    "CVE-2015-4840",
    "CVE-2015-4842",
    "CVE-2015-4843",
    "CVE-2015-4844",
    "CVE-2015-4860",
    "CVE-2015-4871",
    "CVE-2015-4872",
    "CVE-2015-4882",
    "CVE-2015-4883",
    "CVE-2015-4893",
    "CVE-2015-4902",
    "CVE-2015-4903",
    "CVE-2015-5006",
    "CVE-2015-5041",
    "CVE-2015-7575",
    "CVE-2015-7981",
    "CVE-2015-8126",
    "CVE-2015-8472",
    "CVE-2015-8540",
    "CVE-2016-0264",
    "CVE-2016-0363",
    "CVE-2016-0376",
    "CVE-2016-0402",
    "CVE-2016-0448",
    "CVE-2016-0466",
    "CVE-2016-0483",
    "CVE-2016-0494",
    "CVE-2016-0686",
    "CVE-2016-0687",
    "CVE-2016-3422",
    "CVE-2016-3426",
    "CVE-2016-3427",
    "CVE-2016-3443",
    "CVE-2016-3449"
  );
  script_xref(name:"RHSA", value:"2016:1430");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"RHEL 6 : java-1.7.0-ibm and java-1.7.1-ibm (RHSA-2016:1430)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for java-1.7.0-ibm / java-1.7.1-ibm.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2016:1430 advisory.

    IBM Java SE version 7 includes the IBM Java Runtime Environment and the IBM Java Software Development Kit.

    This update upgrades IBM Java SE 7 to versions 7 SR9-FP40 and 7R1 SR3-FP40.

    Security Fix(es):

    * This update fixes multiple vulnerabilities in the IBM Java Runtime Environment and the IBM Java Software
    Development Kit. Further information about these flaws can be found on the IBM Java Security alerts page,
    listed in the References section. (CVE-2015-4734, CVE-2015-4803, CVE-2015-4805, CVE-2015-4806,
    CVE-2015-4810, CVE-2015-4835, CVE-2015-4840, CVE-2015-4842, CVE-2015-4843, CVE-2015-4844, CVE-2015-4860,
    CVE-2015-4871, CVE-2015-4872, CVE-2015-4882, CVE-2015-4883, CVE-2015-4893, CVE-2015-4902, CVE-2015-4903,
    CVE-2015-5006, CVE-2015-5041, CVE-2015-7575, CVE-2015-7981, CVE-2015-8126, CVE-2015-8472, CVE-2015-8540,
    CVE-2016-0264, CVE-2016-0363, CVE-2016-0376, CVE-2016-0402, CVE-2016-0448, CVE-2016-0466, CVE-2016-0483,
    CVE-2016-0494, CVE-2016-0686, CVE-2016-0687, CVE-2016-3422, CVE-2016-3426, CVE-2016-3427, CVE-2016-3443,
    CVE-2016-3449)

    Red Hat would like to thank Andrea Palazzo of Truel IT for reporting the
    CVE-2015-4806 issue.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2016/rhsa-2016_1430.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d1acf66");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:1430");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1233687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1273860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1276416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1281756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1282379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1289841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1291312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1298906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1298957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1299073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1299385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1299441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1324044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1327743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1327749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1328059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1328210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1328618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1328619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1328620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1330986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1331359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1351695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1353209");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL java-1.7.0-ibm / java-1.7.1-ibm packages based on the guidance in RHSA-2016:1430.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3443");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-3427");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(119, 120, 125, 20, 200, 407, 532, 665, 681, 770, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.6/os',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.6/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.7/os',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.7/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.6/os',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.6/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.7/os',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.7.1-ibm-1.7.1.3.40-1jpp.1.el6_7', 'cpu':'s390x', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.1-ibm-1.7.1.3.40-1jpp.1.el6_7', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.1-ibm-devel-1.7.1.3.40-1jpp.1.el6_7', 'cpu':'s390x', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.7.1-ibm-devel-1.7.1.3.40-1jpp.1.el6_7', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.6/os',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.6/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.6/os',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'spacewalk-java-2.0.2-109.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-java-config-2.0.2-109.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-java-lib-2.0.2-109.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-java-oracle-2.0.2-109.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-java-postgresql-2.0.2-109.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-taskomatic-2.0.2-109.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.7/os',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.7/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.7/os',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'spacewalk-java-2.3.8-146.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-java-config-2.3.8-146.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-java-lib-2.3.8-146.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-java-oracle-2.3.8-146.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-java-postgresql-2.3.8-146.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-taskomatic-2.3.8-146.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.7.1-ibm / java-1.7.1-ibm-devel / spacewalk-java / etc');
}
