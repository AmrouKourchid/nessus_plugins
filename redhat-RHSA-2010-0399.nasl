#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0399. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46308);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2007-5935",
    "CVE-2009-0146",
    "CVE-2009-0147",
    "CVE-2009-0166",
    "CVE-2009-0195",
    "CVE-2009-0791",
    "CVE-2009-0799",
    "CVE-2009-0800",
    "CVE-2009-1179",
    "CVE-2009-1180",
    "CVE-2009-1181",
    "CVE-2009-1182",
    "CVE-2009-1183",
    "CVE-2009-3609",
    "CVE-2010-0739",
    "CVE-2010-0827",
    "CVE-2010-1440"
  );
  script_bugtraq_id(
    26469,
    34568,
    34791,
    35195,
    36703,
    39500,
    39966
  );
  script_xref(name:"RHSA", value:"2010:0399");

  script_name(english:"RHEL 4 : tetex (RHSA-2010:0399)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for tetex.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2010:0399 advisory.

    teTeX is an implementation of TeX. TeX takes a text file and a set of
    formatting commands as input, and creates a typesetter-independent DeVice
    Independent (DVI) file as output.

    A buffer overflow flaw was found in the way teTeX processed virtual font
    files when converting DVI files into PostScript. An attacker could create a
    malicious DVI file that would cause the dvips executable to crash or,
    potentially, execute arbitrary code. (CVE-2010-0827)

    Multiple integer overflow flaws were found in the way teTeX processed
    special commands when converting DVI files into PostScript. An attacker
    could create a malicious DVI file that would cause the dvips executable to
    crash or, potentially, execute arbitrary code. (CVE-2010-0739,
    CVE-2010-1440)

    A stack-based buffer overflow flaw was found in the way teTeX processed DVI
    files containing HyperTeX references with long titles, when converting them
    into PostScript. An attacker could create a malicious DVI file that would
    cause the dvips executable to crash. (CVE-2007-5935)

    teTeX embeds a copy of Xpdf, an open source Portable Document Format (PDF)
    file viewer, to allow adding images in PDF format to the generated PDF
    documents. The following issues affect Xpdf code:

    Multiple integer overflow flaws were found in Xpdf's JBIG2 decoder. If a
    local user generated a PDF file from a TeX document, referencing a
    specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
    execute arbitrary code with the privileges of the user running pdflatex.
    (CVE-2009-0147, CVE-2009-1179)

    Multiple integer overflow flaws were found in Xpdf. If a local user
    generated a PDF file from a TeX document, referencing a specially-crafted
    PDF file, it would cause Xpdf to crash or, potentially, execute arbitrary
    code with the privileges of the user running pdflatex. (CVE-2009-0791,
    CVE-2009-3609)

    A heap-based buffer overflow flaw was found in Xpdf's JBIG2 decoder. If a
    local user generated a PDF file from a TeX document, referencing a
    specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
    execute arbitrary code with the privileges of the user running pdflatex.
    (CVE-2009-0195)

    Multiple buffer overflow flaws were found in Xpdf's JBIG2 decoder. If a
    local user generated a PDF file from a TeX document, referencing a
    specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
    execute arbitrary code with the privileges of the user running pdflatex.
    (CVE-2009-0146, CVE-2009-1182)

    Multiple flaws were found in Xpdf's JBIG2 decoder that could lead to the
    freeing of arbitrary memory. If a local user generated a PDF file from a
    TeX document, referencing a specially-crafted PDF file, it would cause
    Xpdf to crash or, potentially, execute arbitrary code with the privileges
    of the user running pdflatex. (CVE-2009-0166, CVE-2009-1180)

    Multiple input validation flaws were found in Xpdf's JBIG2 decoder. If a
    local user generated a PDF file from a TeX document, referencing a
    specially-crafted PDF file, it would cause Xpdf to crash or, potentially,
    execute arbitrary code with the privileges of the user running pdflatex.
    (CVE-2009-0800)

    Multiple denial of service flaws were found in Xpdf's JBIG2 decoder. If a
    local user generated a PDF file from a TeX document, referencing a
    specially-crafted PDF file, it would cause Xpdf to crash. (CVE-2009-0799,
    CVE-2009-1181, CVE-2009-1183)

    Red Hat would like to thank Braden Thomas and Drew Yao of the Apple Product
    Security team, Will Dormann of the CERT/CC, and Alin Rad Pop of Secunia
    Research, for responsibly reporting the Xpdf flaws.

    All users of tetex are advised to upgrade to these updated packages, which
    contain backported patches to correct these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0399.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?758aca02");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=368591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=572914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=572941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=586819");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0399");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL tetex package based on the guidance in RHSA-2010:0399.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1182");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2009-3609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 190, 476, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-xdvi");
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
      {'reference':'tetex-2.0.2-22.0.1.EL4.16', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-2.0.2-22.0.1.EL4.16', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-2.0.2-22.0.1.EL4.16', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-2.0.2-22.0.1.EL4.16', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-2.0.2-22.0.1.EL4.16', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-afm-2.0.2-22.0.1.EL4.16', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-afm-2.0.2-22.0.1.EL4.16', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-afm-2.0.2-22.0.1.EL4.16', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-afm-2.0.2-22.0.1.EL4.16', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-afm-2.0.2-22.0.1.EL4.16', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-doc-2.0.2-22.0.1.EL4.16', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-doc-2.0.2-22.0.1.EL4.16', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-doc-2.0.2-22.0.1.EL4.16', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-doc-2.0.2-22.0.1.EL4.16', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-doc-2.0.2-22.0.1.EL4.16', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-dvips-2.0.2-22.0.1.EL4.16', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-dvips-2.0.2-22.0.1.EL4.16', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-dvips-2.0.2-22.0.1.EL4.16', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-dvips-2.0.2-22.0.1.EL4.16', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-dvips-2.0.2-22.0.1.EL4.16', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-fonts-2.0.2-22.0.1.EL4.16', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-fonts-2.0.2-22.0.1.EL4.16', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-fonts-2.0.2-22.0.1.EL4.16', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-fonts-2.0.2-22.0.1.EL4.16', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-fonts-2.0.2-22.0.1.EL4.16', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-latex-2.0.2-22.0.1.EL4.16', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-latex-2.0.2-22.0.1.EL4.16', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-latex-2.0.2-22.0.1.EL4.16', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-latex-2.0.2-22.0.1.EL4.16', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-latex-2.0.2-22.0.1.EL4.16', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-xdvi-2.0.2-22.0.1.EL4.16', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-xdvi-2.0.2-22.0.1.EL4.16', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-xdvi-2.0.2-22.0.1.EL4.16', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-xdvi-2.0.2-22.0.1.EL4.16', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tetex-xdvi-2.0.2-22.0.1.EL4.16', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tetex / tetex-afm / tetex-doc / tetex-dvips / tetex-fonts / etc');
}
