##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0035. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147374);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/11");

  script_cve_id("CVE-2020-0569", "CVE-2020-0570", "CVE-2020-17507");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : qt5-qtbase Multiple Vulnerabilities (NS-SA-2021-0035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has qt5-qtbase packages installed that are
affected by multiple vulnerabilities:

  - An issue was discovered in Qt through 5.12.9, and 5.13.x through 5.15.x before 5.15.1. read_xbm_body in
    gui/image/qxbmhandler.cpp has a buffer over-read. (CVE-2020-17507)

  - Uncontrolled search path in the QT Library before 5.14.0, 5.12.7 and 5.9.10 may allow an authenticated
    user to potentially enable elevation of privilege via local access. (CVE-2020-0570)

  - Out of bounds write in Intel(R) PROSet/Wireless WiFi products on Windows 10 may allow an authenticated
    user to potentially enable denial of service via local access. (CVE-2020-0569)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0035");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qt5-qtbase packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0570");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'qt5-qtbase-5.9.7-5.el7_9',
    'qt5-qtbase-common-5.9.7-5.el7_9',
    'qt5-qtbase-devel-5.9.7-5.el7_9',
    'qt5-qtbase-doc-5.9.7-5.el7_9',
    'qt5-qtbase-examples-5.9.7-5.el7_9',
    'qt5-qtbase-gui-5.9.7-5.el7_9',
    'qt5-qtbase-mysql-5.9.7-5.el7_9',
    'qt5-qtbase-odbc-5.9.7-5.el7_9',
    'qt5-qtbase-postgresql-5.9.7-5.el7_9',
    'qt5-qtbase-static-5.9.7-5.el7_9',
    'qt5-rpm-macros-5.9.7-5.el7_9'
  ],
  'CGSL MAIN 5.04': [
    'qt5-qtbase-5.9.7-5.el7_9',
    'qt5-qtbase-common-5.9.7-5.el7_9',
    'qt5-qtbase-devel-5.9.7-5.el7_9',
    'qt5-qtbase-doc-5.9.7-5.el7_9',
    'qt5-qtbase-examples-5.9.7-5.el7_9',
    'qt5-qtbase-gui-5.9.7-5.el7_9',
    'qt5-qtbase-mysql-5.9.7-5.el7_9',
    'qt5-qtbase-odbc-5.9.7-5.el7_9',
    'qt5-qtbase-postgresql-5.9.7-5.el7_9',
    'qt5-qtbase-static-5.9.7-5.el7_9',
    'qt5-rpm-macros-5.9.7-5.el7_9'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qt5-qtbase');
}
