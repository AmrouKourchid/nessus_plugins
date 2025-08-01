##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0092. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143935);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/05");

  script_cve_id(
    "CVE-2018-15518",
    "CVE-2018-19869",
    "CVE-2018-19870",
    "CVE-2018-19871",
    "CVE-2018-19872",
    "CVE-2018-19873"
  );
  script_bugtraq_id(106286, 106327, 106338);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : qt Multiple Vulnerabilities (NS-SA-2020-0092)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has qt packages installed that are affected by
multiple vulnerabilities:

  - An issue was discovered in Qt 5.11. A malformed PPM image causes a division by zero and a crash in
    qppmhandler.cpp. (CVE-2018-19872)

  - An issue was discovered in Qt before 5.11.3. A malformed GIF image causes a NULL pointer dereference in
    QGifHandler resulting in a segmentation fault. (CVE-2018-19870)

  - An issue was discovered in Qt before 5.11.3. QBmpHandler has a buffer overflow via BMP data.
    (CVE-2018-19873)

  - An issue was discovered in Qt before 5.11.3. There is QTgaFile Uncontrolled Resource Consumption.
    (CVE-2018-19871)

  - QXmlStream in Qt 5.x before 5.11.3 has a double-free or corruption during parsing of a specially crafted
    illegal XML document. (CVE-2018-15518)

  - An issue was discovered in Qt before 5.11.3. A malformed SVG image causes a segmentation fault in
    qsvghandler.cpp. (CVE-2018-19869)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0092");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qt packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19873");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.05': [
    'qt-4.8.7-8.el7',
    'qt-assistant-4.8.7-8.el7',
    'qt-config-4.8.7-8.el7',
    'qt-debuginfo-4.8.7-8.el7',
    'qt-demos-4.8.7-8.el7',
    'qt-devel-4.8.7-8.el7',
    'qt-devel-private-4.8.7-8.el7',
    'qt-doc-4.8.7-8.el7',
    'qt-examples-4.8.7-8.el7',
    'qt-mysql-4.8.7-8.el7',
    'qt-odbc-4.8.7-8.el7',
    'qt-postgresql-4.8.7-8.el7',
    'qt-qdbusviewer-4.8.7-8.el7',
    'qt-qvfb-4.8.7-8.el7',
    'qt-x11-4.8.7-8.el7'
  ],
  'CGSL MAIN 5.05': [
    'qt-4.8.7-8.el7',
    'qt-assistant-4.8.7-8.el7',
    'qt-config-4.8.7-8.el7',
    'qt-debuginfo-4.8.7-8.el7',
    'qt-demos-4.8.7-8.el7',
    'qt-devel-4.8.7-8.el7',
    'qt-devel-private-4.8.7-8.el7',
    'qt-doc-4.8.7-8.el7',
    'qt-examples-4.8.7-8.el7',
    'qt-mysql-4.8.7-8.el7',
    'qt-odbc-4.8.7-8.el7',
    'qt-postgresql-4.8.7-8.el7',
    'qt-qdbusviewer-4.8.7-8.el7',
    'qt-qvfb-4.8.7-8.el7',
    'qt-x11-4.8.7-8.el7'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qt');
}
