#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7055-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208094);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id("CVE-2024-3596");
  script_xref(name:"USN", value:"7055-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS : FreeRADIUS vulnerability (USN-7055-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-7055-1 advisory.

    Goldberg, Miro Haller, Nadia Heninger, Mike Milano, Dan Shumow, Marc Stevens, and Adam Suhl discovered
    that FreeRADIUS incorrectly authenticated certain responses. An attacker able to intercept communications
    between a RADIUS client and server could possibly use this issue to forge responses, bypass
    authentication, and access network devices and services.

    This update introduces new configuration options called limit_proxy_state and
    require_message_authenticator that default to auto but should be set to yes once all RADIUS devices
    have been upgraded on a network.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7055-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/R:A");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-iodbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-memcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-yubikey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreeradius-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreeradius3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'freeradius', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-common', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-config', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-dhcp', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-iodbc', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-krb5', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-ldap', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-memcached', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-mysql', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-postgresql', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-python3', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-redis', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-rest', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-utils', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'freeradius-yubikey', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libfreeradius-dev', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'libfreeradius3', 'pkgver': '3.0.20+dfsg-3ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'freeradius', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-common', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-config', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-dhcp', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-iodbc', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-krb5', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-ldap', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-memcached', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-mysql', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-postgresql', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-python3', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-redis', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-rest', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-utils', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'freeradius-yubikey', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libfreeradius-dev', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libfreeradius3', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.3'},
    {'osver': '24.04', 'pkgname': 'freeradius', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-common', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-config', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-dhcp', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-iodbc', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-krb5', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-ldap', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-memcached', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-mysql', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-postgresql', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-python3', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-redis', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-rest', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-utils', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'freeradius-yubikey', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'libfreeradius-dev', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'},
    {'osver': '24.04', 'pkgname': 'libfreeradius3', 'pkgver': '3.2.5+dfsg-3~ubuntu24.04.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freeradius / freeradius-common / freeradius-config / etc');
}
