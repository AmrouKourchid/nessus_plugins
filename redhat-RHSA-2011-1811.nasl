#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1811. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57081);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2009-4274", "CVE-2011-4516", "CVE-2011-4517");
  script_bugtraq_id(38164, 50992);
  script_xref(name:"RHSA", value:"2011:1811");

  script_name(english:"RHEL 4 / 5 : netpbm (RHSA-2011:1811)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for netpbm.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 / 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2011:1811 advisory.

    The netpbm packages contain a library of functions which support programs
    for handling various graphics file formats, including .pbm (Portable Bit
    Map), .pgm (Portable Gray Map), .pnm (Portable Any Map), .ppm (Portable
    Pixel Map), and others.

    Two heap-based buffer overflow flaws were found in the embedded JasPer
    library, which is used to provide support for Part 1 of the JPEG 2000 image
    compression standard in the jpeg2ktopam and pamtojpeg2k tools. An attacker
    could create a malicious JPEG 2000 compressed image file that could cause
    jpeg2ktopam to crash or, potentially, execute arbitrary code with the
    privileges of the user running jpeg2ktopam. These flaws do not affect
    pamtojpeg2k. (CVE-2011-4516, CVE-2011-4517)

    A stack-based buffer overflow flaw was found in the way the xpmtoppm tool
    processed X PixMap (XPM) image files. An attacker could create a malicious
    XPM file that would cause xpmtoppm to crash or, potentially, execute
    arbitrary code with the privileges of the user running xpmtoppm.
    (CVE-2009-4274)

    Red Hat would like to thank Jonathan Foote of the CERT Coordination Center
    for reporting the CVE-2011-4516 and CVE-2011-4517 issues.

    All users of netpbm are advised to upgrade to these updated packages,
    which contain backported patches to correct these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2011/rhsa-2011_1811.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3504428b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:1811");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=747726");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL netpbm package based on the guidance in RHSA-2011:1811.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-4274");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2011-4517");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(121, 122);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netpbm-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['4','5'])) audit(AUDIT_OS_NOT, 'Red Hat 4.x / 5.x', 'Red Hat ' + os_ver);

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
      {'reference':'netpbm-10.35.58-8.el4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el4', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el4', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el4', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el4', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el4', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el4', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el4', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el4', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el4', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el4', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el4', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el4', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/5/5Client/i386/debug',
      'content/dist/rhel/client/5/5Client/i386/os',
      'content/dist/rhel/client/5/5Client/i386/source/SRPMS',
      'content/dist/rhel/client/5/5Client/x86_64/debug',
      'content/dist/rhel/client/5/5Client/x86_64/os',
      'content/dist/rhel/client/5/5Client/x86_64/source/SRPMS',
      'content/dist/rhel/power/5/5Server/ppc/debug',
      'content/dist/rhel/power/5/5Server/ppc/os',
      'content/dist/rhel/power/5/5Server/ppc/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/debug',
      'content/dist/rhel/server/5/5Server/i386/os',
      'content/dist/rhel/server/5/5Server/i386/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/debug',
      'content/dist/rhel/server/5/5Server/x86_64/os',
      'content/dist/rhel/server/5/5Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/debug',
      'content/dist/rhel/system-z/5/5Server/s390x/os',
      'content/dist/rhel/system-z/5/5Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/debug',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/debug',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/os',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/os',
      'content/dist/rhel/workstation/5/5Client/i386/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/5/i386/debug',
      'content/fastrack/rhel/client/5/i386/os',
      'content/fastrack/rhel/client/5/i386/source/SRPMS',
      'content/fastrack/rhel/client/5/x86_64/debug',
      'content/fastrack/rhel/client/5/x86_64/os',
      'content/fastrack/rhel/client/5/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/5/ppc/debug',
      'content/fastrack/rhel/power/5/ppc/os',
      'content/fastrack/rhel/power/5/ppc/source/SRPMS',
      'content/fastrack/rhel/server/5/i386/debug',
      'content/fastrack/rhel/server/5/i386/os',
      'content/fastrack/rhel/server/5/i386/source/SRPMS',
      'content/fastrack/rhel/server/5/x86_64/debug',
      'content/fastrack/rhel/server/5/x86_64/os',
      'content/fastrack/rhel/server/5/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/5/s390x/debug',
      'content/fastrack/rhel/system-z/5/s390x/os',
      'content/fastrack/rhel/system-z/5/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/5/i386/debug',
      'content/fastrack/rhel/workstation/5/i386/desktop/debug',
      'content/fastrack/rhel/workstation/5/i386/desktop/os',
      'content/fastrack/rhel/workstation/5/i386/desktop/source/SRPMS',
      'content/fastrack/rhel/workstation/5/i386/os',
      'content/fastrack/rhel/workstation/5/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/5/x86_64/debug',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/debug',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/os',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/source/SRPMS',
      'content/fastrack/rhel/workstation/5/x86_64/os',
      'content/fastrack/rhel/workstation/5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'netpbm-10.35.58-8.el5_7.3', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el5_7.3', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el5_7.3', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el5_7.3', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el5_7.3', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-10.35.58-8.el5_7.3', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el5_7.3', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el5_7.3', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el5_7.3', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el5_7.3', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el5_7.3', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-devel-10.35.58-8.el5_7.3', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el5_7.3', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el5_7.3', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el5_7.3', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netpbm-progs-10.35.58-8.el5_7.3', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'netpbm / netpbm-devel / netpbm-progs');
}
