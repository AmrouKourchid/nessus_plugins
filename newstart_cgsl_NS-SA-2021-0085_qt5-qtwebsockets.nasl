##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0085. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147358);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/11");

  script_cve_id("CVE-2018-21035");

  script_name(english:"NewStart CGSL MAIN 6.02 : qt5-qtwebsockets Vulnerability (NS-SA-2021-0085)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has qt5-qtwebsockets packages installed that are affected by a
vulnerability:

  - In Qt through 5.14.1, the WebSocket implementation accepts up to 2GB for frames and 2GB for messages.
    Smaller limits cannot be configured. This makes it easier for attackers to cause a denial of service
    (memory consumption). (CVE-2018-21035)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0085");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qt5-qtwebsockets packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-21035");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/28");
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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'qt5-qtwebsockets-5.12.5-2.el8',
    'qt5-qtwebsockets-debuginfo-5.12.5-2.el8',
    'qt5-qtwebsockets-debugsource-5.12.5-2.el8',
    'qt5-qtwebsockets-devel-5.12.5-2.el8',
    'qt5-qtwebsockets-devel-debuginfo-5.12.5-2.el8',
    'qt5-qtwebsockets-examples-5.12.5-2.el8',
    'qt5-qtwebsockets-examples-debuginfo-5.12.5-2.el8',
    'qt5-qtwebsockets-tests-5.12.5-2.el8',
    'qt5-qtwebsockets-tests-debuginfo-5.12.5-2.el8'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qt5-qtwebsockets');
}
