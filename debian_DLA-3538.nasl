#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3538. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(180038);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2013-7484",
    "CVE-2019-17382",
    "CVE-2022-43515",
    "CVE-2023-29450",
    "CVE-2023-29451",
    "CVE-2023-29454",
    "CVE-2023-29455",
    "CVE-2023-29456",
    "CVE-2023-29457"
  );

  script_name(english:"Debian DLA-3538-1 : zabbix - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3538 advisory.

  - Zabbix before 5.0 represents passwords in the users table with unsalted MD5. (CVE-2013-7484)

  - An issue was discovered in zabbix.php?action=dashboard.view&dashboardid=1 in Zabbix through 4.4. An
    attacker can bypass the login page and access the dashboard page, and then create a Dashboard, Report,
    Screen, or Map without any Username/Password (i.e., anonymously). All created elements
    (Dashboard/Report/Screen/Map) are accessible by other users and by an admin. (CVE-2019-17382)

  - Zabbix Frontend provides a feature that allows admins to maintain the installation and ensure that only
    certain IP addresses can access it. In this way, any user will not be able to access the Zabbix Frontend
    while it is being maintained and possible sensitive data will be prevented from being disclosed. An
    attacker can bypass this protection and access the instance using IP address not listed in the defined
    range. (CVE-2022-43515)

  - JavaScript pre-processing can be used by the attacker to gain access to the file system (read-only access
    on behalf of user zabbix) on the Zabbix Server or Zabbix Proxy, potentially leading to unauthorized
    access to sensitive data. (CVE-2023-29450)

  - Specially crafted string can cause a buffer overrun in the JSON parser library leading to a crash of the
    Zabbix Server or a Zabbix Proxy. (CVE-2023-29451)

  - Stored or persistent cross-site scripting (XSS) is a type of XSS where the attacker first sends the
    payload to the web application, then the application saves the payload (e.g., in a database or server-side
    text files), and finally, the application unintentionally executes the payload for every victim visiting
    its web pages. (CVE-2023-29454)

  - Reflected XSS attacks, also known as non-persistent attacks, occur when a malicious script is reflected
    off a web application to the victim's browser. The script is activated through a link, which sends a
    request to a website with a vulnerability that enables execution of malicious scripts. (CVE-2023-29455)

  - URL validation scheme receives input from a user and then parses it to identify its various components.
    The validation scheme can ensure that all URL components comply with internet standards. (CVE-2023-29456)

  - Reflected XSS attacks, occur when a malicious script is reflected off a web application to the victim's
    browser. The script can be activated through Action form fields, which can be sent as request to a website
    with a vulnerability that enables execution of malicious scripts. (CVE-2023-29457)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1026847");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/zabbix");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3538");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-7484");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-17382");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43515");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29450");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29451");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29455");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29456");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29457");
  script_set_attribute(attribute:"solution", value:
"Upgrade the zabbix packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17382");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-43515");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'zabbix', 'reference': '1:4.0.4+dfsg-1+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'zabbix');
}
