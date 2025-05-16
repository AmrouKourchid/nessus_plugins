#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0982. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79039);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2013-5878",
    "CVE-2013-5884",
    "CVE-2013-5887",
    "CVE-2013-5888",
    "CVE-2013-5889",
    "CVE-2013-5896",
    "CVE-2013-5898",
    "CVE-2013-5899",
    "CVE-2013-5907",
    "CVE-2013-5910",
    "CVE-2013-6629",
    "CVE-2013-6954",
    "CVE-2014-0368",
    "CVE-2014-0373",
    "CVE-2014-0375",
    "CVE-2014-0376",
    "CVE-2014-0387",
    "CVE-2014-0403",
    "CVE-2014-0410",
    "CVE-2014-0411",
    "CVE-2014-0415",
    "CVE-2014-0416",
    "CVE-2014-0417",
    "CVE-2014-0422",
    "CVE-2014-0423",
    "CVE-2014-0424",
    "CVE-2014-0428",
    "CVE-2014-0429",
    "CVE-2014-0446",
    "CVE-2014-0449",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-0878",
    "CVE-2014-1876",
    "CVE-2014-2398",
    "CVE-2014-2401",
    "CVE-2014-2409",
    "CVE-2014-2412",
    "CVE-2014-2414",
    "CVE-2014-2420",
    "CVE-2014-2421",
    "CVE-2014-2423",
    "CVE-2014-2427",
    "CVE-2014-2428"
  );
  script_xref(name:"RHSA", value:"2014:0982");

  script_name(english:"RHEL 5 / 6 : Red Hat Network Satellite server IBM Java Runtime (RHSA-2014:0982)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat Network Satellite server IBM Java Runtime.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:0982 advisory.

    This update corrects several security vulnerabilities in the IBM Java
    Runtime Environment shipped as part of Red Hat Network Satellite Server
    5.4, 5.5, and 5.6. In a typical operating environment, these are of low
    security risk as the runtime is not used on untrusted applets.

    Several flaws were fixed in the IBM Java 2 Runtime Environment.
    (CVE-2013-5878, CVE-2013-5884, CVE-2013-5887, CVE-2013-5888, CVE-2013-5889,
    CVE-2013-5896, CVE-2013-5898, CVE-2013-5899, CVE-2013-5907, CVE-2013-5910,
    CVE-2013-6629, CVE-2013-6954, CVE-2014-0368, CVE-2014-0373, CVE-2014-0375,
    CVE-2014-0376, CVE-2014-0387, CVE-2014-0403, CVE-2014-0410, CVE-2014-0411,
    CVE-2014-0415, CVE-2014-0416, CVE-2014-0417, CVE-2014-0422, CVE-2014-0423,
    CVE-2014-0424, CVE-2014-0428, CVE-2014-0429, CVE-2014-0446, CVE-2014-0449,
    CVE-2014-0451, CVE-2014-0452, CVE-2014-0453, CVE-2014-0457, CVE-2014-0458,
    CVE-2014-0460, CVE-2014-0461, CVE-2014-0878, CVE-2014-1876, CVE-2014-2398,
    CVE-2014-2401, CVE-2014-2409, CVE-2014-2412, CVE-2014-2414, CVE-2014-2420,
    CVE-2014-2421, CVE-2014-2423, CVE-2014-2427, CVE-2014-2428)

    Users of Red Hat Network Satellite Server 5.4, 5.5, and 5.6 are advised to
    upgrade to these updated packages, which contain the IBM Java SE 6 SR16
    release. For this update to take effect, Red Hat Network Satellite Server
    must be restarted (/usr/sbin/rhn-satellite restart), as well as all
    running instances of IBM Java.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2014/rhsa-2014_0982.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d59ec110");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/developerworks/java/jdk/alerts/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:0982");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1031734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1045561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1051519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1051528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1051699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1051823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1051911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1051912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1051923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1052915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1052919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1052942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1053518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1060907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1086632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1086645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1088025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1088027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1088028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1088030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1088031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1097345");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Network Satellite server IBM Java Runtime package based on the guidance in RHSA-2014:0982.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2421");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-6629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(377, 456);
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/5/5Server/i386/satellite/5.4/os',
      'content/dist/rhel/server/5/5Server/i386/satellite/5.4/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.4/os',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.4/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.5/os',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.5/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.6/os',
      'content/dist/rhel/server/5/5Server/x86_64/satellite/5.6/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.4/os',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.4/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.5/os',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.5/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.6/os',
      'content/dist/rhel/system-z/5/5Server/s390x/satellite/5.6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.6.0-ibm-1.6.0.16.0-1jpp.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.16.0-1jpp.1.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.16.0-1jpp.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.16.0-1jpp.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.16.0-1jpp.1.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.16.0-1jpp.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.4/os',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.5/os',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.5/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.6/os',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.6/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.4/os',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.4/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.5/os',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.5/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.6/os',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.6.0-ibm-1.6.0.16.0-1jpp.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-1.6.0.16.0-1jpp.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.16.0-1jpp.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.6.0-ibm-devel-1.6.0.16.0-1jpp.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.6.0-ibm / java-1.6.0-ibm-devel');
}
