#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0154. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46271);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2009-0689",
    "CVE-2009-1571",
    "CVE-2009-2462",
    "CVE-2009-2463",
    "CVE-2009-2466",
    "CVE-2009-2470",
    "CVE-2009-3072",
    "CVE-2009-3075",
    "CVE-2009-3076",
    "CVE-2009-3077",
    "CVE-2009-3274",
    "CVE-2009-3376",
    "CVE-2009-3380",
    "CVE-2009-3384",
    "CVE-2009-3979",
    "CVE-2010-0159",
    "CVE-2010-0163",
    "CVE-2010-0169",
    "CVE-2010-0171"
  );
  script_bugtraq_id(
    35765,
    35769,
    35776,
    36343,
    36851,
    36852,
    36867,
    36871,
    37361,
    38286,
    38287
  );
  script_xref(name:"RHSA", value:"2010:0154");

  script_name(english:"RHEL 4 : thunderbird (RHSA-2010:0154)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for thunderbird.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2010:0154 advisory.

    Mozilla Thunderbird is a standalone mail and newsgroup client.

    Several flaws were found in the processing of malformed HTML mail content.
    An HTML mail message containing malicious content could cause Thunderbird
    to crash or, potentially, execute arbitrary code with the privileges of the
    user running Thunderbird. (CVE-2009-2462, CVE-2009-2463, CVE-2009-2466,
    CVE-2009-3072, CVE-2009-3075, CVE-2009-3380, CVE-2009-3979, CVE-2010-0159)

    A use-after-free flaw was found in Thunderbird. An attacker could use this
    flaw to crash Thunderbird or, potentially, execute arbitrary code with the
    privileges of the user running Thunderbird. (CVE-2009-3077)

    A heap-based buffer overflow flaw was found in the Thunderbird string to
    floating point conversion routines. An HTML mail message containing
    malicious JavaScript could crash Thunderbird or, potentially, execute
    arbitrary code with the privileges of the user running Thunderbird.
    (CVE-2009-0689)

    A use-after-free flaw was found in Thunderbird. Under low memory
    conditions, viewing an HTML mail message containing malicious content could
    result in Thunderbird executing arbitrary code with the privileges of the
    user running Thunderbird. (CVE-2009-1571)

    A flaw was found in the way Thunderbird created temporary file names for
    downloaded files. If a local attacker knows the name of a file Thunderbird
    is going to download, they can replace the contents of that file with
    arbitrary contents. (CVE-2009-3274)

    A flaw was found in the way Thunderbird displayed a right-to-left override
    character when downloading a file. In these cases, the name displayed in
    the title bar differed from the name displayed in the dialog body. An
    attacker could use this flaw to trick a user into downloading a file that
    has a file name or extension that is different from what the user expected.
    (CVE-2009-3376)

    A flaw was found in the way Thunderbird processed SOCKS5 proxy replies. A
    malicious SOCKS5 server could send a specially-crafted reply that would
    cause Thunderbird to crash. (CVE-2009-2470)

    Descriptions in the dialogs when adding and removing PKCS #11 modules were
    not informative. An attacker able to trick a user into installing a
    malicious PKCS #11 module could use this flaw to install their own
    Certificate Authority certificates on a user's machine, making it possible
    to trick the user into believing they are viewing trusted content or,
    potentially, execute arbitrary code with the privileges of the user running
    Thunderbird. (CVE-2009-3076)

    All Thunderbird users should upgrade to this updated package, which
    resolves these issues. All running instances of Thunderbird must be
    restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0154.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a161a034");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=524815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=566047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=566050");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0154");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL thunderbird package based on the guidance in RHSA-2010:0154.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0159");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-0171");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(190, 79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '4')) audit(AUDIT_OS_NOT, 'Red Hat 4.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/as/4/4AS/i386/os',
      'content/dist/rhel/as/4/4AS/i386/source/SRPMS',
      'content/dist/rhel/as/4/4AS/x86_64/os',
      'content/dist/rhel/as/4/4AS/x86_64/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/i386/os',
      'content/dist/rhel/desktop/4/4Desktop/i386/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/x86_64/os',
      'content/dist/rhel/desktop/4/4Desktop/x86_64/source/SRPMS',
      'content/dist/rhel/es/4/4ES/i386/os',
      'content/dist/rhel/es/4/4ES/i386/source/SRPMS',
      'content/dist/rhel/es/4/4ES/x86_64/os',
      'content/dist/rhel/es/4/4ES/x86_64/source/SRPMS',
      'content/dist/rhel/power/4/4AS/ppc/os',
      'content/dist/rhel/power/4/4AS/ppc/source/SRPMS',
      'content/dist/rhel/system-z/4/4AS/s390/os',
      'content/dist/rhel/system-z/4/4AS/s390/source/SRPMS',
      'content/dist/rhel/system-z/4/4AS/s390x/os',
      'content/dist/rhel/system-z/4/4AS/s390x/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/i386/os',
      'content/dist/rhel/ws/4/4WS/i386/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/x86_64/os',
      'content/dist/rhel/ws/4/4WS/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'thunderbird-1.5.0.12-25.el4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'thunderbird-1.5.0.12-25.el4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'thunderbird-1.5.0.12-25.el4', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'thunderbird-1.5.0.12-25.el4', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'thunderbird-1.5.0.12-25.el4', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
