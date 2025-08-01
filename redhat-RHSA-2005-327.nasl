#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:327. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17645);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2005-0468", "CVE-2005-0469");
  script_xref(name:"RHSA", value:"2005:327");

  script_name(english:"RHEL 4 : telnet (RHSA-2005:327)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for telnet.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2005:327 advisory.

    The telnet package provides a command line telnet client. The telnet-server
    package includes a telnet daemon, telnetd, that supports remote login to
    the host machine.

    Two buffer overflow flaws were discovered in the way the telnet client
    handles messages from a server.  An attacker may be able to execute
    arbitrary code on a victim's machine if the victim can be tricked into
    connecting to a malicious telnet server. The Common Vulnerabilities and
    Exposures project (cve.mitre.org) has assigned the names CAN-2005-0468
    and CAN-2005-0469 to these issues.

    Additionally, the following bugs have been fixed in these erratum packages
    for Red Hat Enterprise Linux 2.1 and Red Hat Enterprise Linux 3:

    - telnetd could loop on an error in the child side process

    - There was a race condition in telnetd on a wtmp lock on some occasions

    - The command line in the process table was sometimes too long and caused
    bad output from the ps command

    - The 8-bit binary option was not working

    Users of telnet should upgrade to this updated package, which contains
    backported patches to correct these issues.

    Red Hat would like to thank iDEFENSE for their responsible disclosure of
    this issue.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=126858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=145004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=145636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=147003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=151297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=151301");
  # http://www.idefense.com/application/poi/display?id=221&type=vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c9ef05e");
  # http://www.idefense.com/application/poi/display?id=220&type=vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd66aadd");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2005/rhsa-2005_327.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47f4720e");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2005:327");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL telnet package based on the guidance in RHSA-2005:327.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0469");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2005-0468");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:telnet-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2005-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'telnet-0.17-31.EL4.2', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-0.17-31.EL4.2', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-0.17-31.EL4.2', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-0.17-31.EL4.2', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-0.17-31.EL4.2', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-server-0.17-31.EL4.2', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-server-0.17-31.EL4.2', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-server-0.17-31.EL4.2', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-server-0.17-31.EL4.2', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'telnet-server-0.17-31.EL4.2', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'telnet / telnet-server');
}
