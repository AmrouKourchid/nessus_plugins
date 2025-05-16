#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4969-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150030);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2021-25217");
  script_xref(name:"USN", value:"4969-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : DHCP vulnerability (USN-4969-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-4969-1 advisory.

    Jon Franklin and Pawel Wieczorkiewicz discovered that DHCP incorrectly handled lease file parsing. A
    remote attacker could possibly use this issue to cause DHCP to crash, resulting in a denial of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4969-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-client-ddns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:isc-dhcp-server-ldap");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'isc-dhcp-client', 'pkgver': '4.3.5-3ubuntu7.3'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-client-ddns', 'pkgver': '4.3.5-3ubuntu7.3'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-client-udeb', 'pkgver': '4.3.5-3ubuntu7.3'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-common', 'pkgver': '4.3.5-3ubuntu7.3'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-dev', 'pkgver': '4.3.5-3ubuntu7.3'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-relay', 'pkgver': '4.3.5-3ubuntu7.3'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-server', 'pkgver': '4.3.5-3ubuntu7.3'},
    {'osver': '18.04', 'pkgname': 'isc-dhcp-server-ldap', 'pkgver': '4.3.5-3ubuntu7.3'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-client', 'pkgver': '4.4.1-2.1ubuntu5.20.04.2'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-client-ddns', 'pkgver': '4.4.1-2.1ubuntu5.20.04.2'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-client-udeb', 'pkgver': '4.4.1-2.1ubuntu5.20.04.2'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-common', 'pkgver': '4.4.1-2.1ubuntu5.20.04.2'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-dev', 'pkgver': '4.4.1-2.1ubuntu5.20.04.2'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-relay', 'pkgver': '4.4.1-2.1ubuntu5.20.04.2'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-server', 'pkgver': '4.4.1-2.1ubuntu5.20.04.2'},
    {'osver': '20.04', 'pkgname': 'isc-dhcp-server-ldap', 'pkgver': '4.4.1-2.1ubuntu5.20.04.2'}
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
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'isc-dhcp-client / isc-dhcp-client-ddns / isc-dhcp-client-udeb / etc');
}
