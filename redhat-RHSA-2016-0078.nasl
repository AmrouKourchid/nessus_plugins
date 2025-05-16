#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0078. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(88479);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2014-8500",
    "CVE-2015-5477",
    "CVE-2015-5722",
    "CVE-2015-8000"
  );
  script_xref(name:"RHSA", value:"2016:0078");

  script_name(english:"RHEL 6 : bind (RHSA-2016:0078)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for bind.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2016:0078 advisory.

    The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
    Name System (DNS) protocols. BIND includes a DNS server (named); a resolver
    library (routines for applications to use when interfacing with DNS); and
    tools for verifying that the DNS server is operating correctly.

    A denial of service flaw was found in the way BIND followed DNS
    delegations. A remote attacker could use a specially crafted zone
    containing a large number of referrals which, when looked up and processed,
    would cause named to use excessive amounts of memory or crash.
    (CVE-2014-8500)

    A flaw was found in the way BIND handled requests for TKEY DNS resource
    records. A remote attacker could use this flaw to make named (functioning
    as an authoritative DNS server or a DNS resolver) exit unexpectedly with an
    assertion failure via a specially crafted DNS request packet.
    (CVE-2015-5477)

    A denial of service flaw was found in the way BIND parsed certain malformed
    DNSSEC keys. A remote attacker could use this flaw to send a specially
    crafted DNS query (for example, a query requiring a response from a zone
    containing a deliberately malformed key) that would cause named functioning
    as a validating resolver to crash. (CVE-2015-5722)

    A denial of service flaw was found in the way BIND processed certain
    records with malformed class attributes. A remote attacker could use this
    flaw to send a query to request a cached record with a malformed class
    attribute that would cause named functioning as an authoritative or
    recursive server to crash. (CVE-2015-8000)

    Note: This issue affects authoritative servers as well as recursive
    servers, however authoritative servers are at limited risk if they perform
    authentication when making recursive queries to resolve addresses for
    servers listed in NS RRSETs.

    Red Hat would like to thank ISC for reporting the CVE-2015-5477,
    CVE-2015-5722, and CVE-2015-8000 issues. Upstream acknowledges Jonathan
    Foote as the original reporter of CVE-2015-5477, and Hanno Bck as the
    original reporter of CVE-2015-5722.

    All bind users are advised to upgrade to these updated packages, which
    contain backported patches to correct these issues. After installing the
    update, the BIND daemon (named) will be restarted automatically.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2016/rhsa-2016_0078.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f713927");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:0078");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1171912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1247361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1259087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1291176");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01216");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01272");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01287");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01317");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL bind package based on the guidance in RHSA-2016:0078.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5722");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-5477");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 400, 617);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.5");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6.4','6.5'])) audit(AUDIT_OS_NOT, 'Red Hat 6.4 / 6.5', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.4/x86_64/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/os',
      'content/aus/rhel/server/6/6.4/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.4/x86_64/os',
      'content/aus/rhel/server/6/6.4/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bind-9.8.2-0.17.rc1.el6_4.7', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.17.rc1.el6_4.7', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.17.rc1.el6_4.7', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.17.rc1.el6_4.7', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.17.rc1.el6_4.7', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.17.rc1.el6_4.7', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.17.rc1.el6_4.7', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.17.rc1.el6_4.7', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.5/x86_64/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/os',
      'content/aus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.5/x86_64/os',
      'content/aus/rhel/server/6/6.5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bind-9.8.2-0.23.rc1.el6_5.2', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.23.rc1.el6_5.2', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.23.rc1.el6_5.2', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.23.rc1.el6_5.2', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.23.rc1.el6_5.2', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.23.rc1.el6_5.2', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.23.rc1.el6_5.2', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.23.rc1.el6_5.2', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
    'Advanced Update Support repository.\n' +
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-devel / bind-libs / bind-sdb / bind-utils');
}
