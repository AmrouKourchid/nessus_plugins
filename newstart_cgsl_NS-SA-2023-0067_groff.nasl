#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0067. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187343);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/27");

  script_cve_id("CVE-2009-5044", "CVE-2009-5080", "CVE-2009-5081");

  script_name(english:"NewStart CGSL MAIN 5.04 : groff Multiple Vulnerabilities (NS-SA-2023-0067)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has groff packages installed that are affected by multiple
vulnerabilities:

  - contrib/pdfmark/pdfroff.sh in GNU troff (aka groff) before 1.21 allows local users to overwrite arbitrary
    files via a symlink attack on a pdf#####.tmp temporary file. (CVE-2009-5044)

  - The (1) contrib/eqn2graph/eqn2graph.sh, (2) contrib/grap2graph/grap2graph.sh, and (3)
    contrib/pic2graph/pic2graph.sh scripts in GNU troff (aka groff) 1.21 and earlier do not properly handle
    certain failed attempts to create temporary directories, which might allow local users to overwrite
    arbitrary files via a symlink attack on a file in a temporary directory, a different vulnerability than
    CVE-2004-1296. (CVE-2009-5080)

  - The (1) config.guess, (2) contrib/groffer/perl/groffer.pl, and (3) contrib/groffer/perl/roff2.pl scripts
    in GNU troff (aka groff) 1.21 and earlier use an insufficient number of X characters in the template
    argument to the tempfile function, which makes it easier for local users to overwrite arbitrary files via
    a symlink attack on a temporary file, a different vulnerability than CVE-2004-0969. (CVE-2009-5081)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0067");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-5044");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-5080");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-5081");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL groff packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-5081");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:groff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:groff-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:groff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:groff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:groff-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:groff-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 5.04': [
    'groff-1.22.2-8.el7.cgslv5_4.0.1.ga313f56',
    'groff-base-1.22.2-8.el7.cgslv5_4.0.1.ga313f56',
    'groff-debuginfo-1.22.2-8.el7.cgslv5_4.0.1.ga313f56',
    'groff-doc-1.22.2-8.el7.cgslv5_4.0.1.ga313f56',
    'groff-perl-1.22.2-8.el7.cgslv5_4.0.1.ga313f56',
    'groff-x11-1.22.2-8.el7.cgslv5_4.0.1.ga313f56'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'groff');
}
