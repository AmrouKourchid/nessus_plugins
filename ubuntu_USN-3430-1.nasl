#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3430-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103641);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-14491",
    "CVE-2017-14492",
    "CVE-2017-14493",
    "CVE-2017-14494",
    "CVE-2017-14495",
    "CVE-2017-14496"
  );
  script_xref(name:"USN", value:"3430-1");
  script_xref(name:"IAVA", value:"2017-A-0284-S");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Dnsmasq vulnerabilities (USN-3430-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3430-1 advisory.

    Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher discovered that Dnsmasq incorrectly
    handled DNS requests. A remote attacker could use this issue to cause Dnsmasq to crash, resulting in a
    denial of service, or possibly execute arbitrary code. (CVE-2017-14491)

    Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher discovered that Dnsmasq incorrectly
    handled IPv6 router advertisements. A remote attacker could use this issue to cause Dnsmasq to crash,
    resulting in a denial of service, or possibly execute arbitrary code. (CVE-2017-14492)

    Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher discovered that Dnsmasq incorrectly
    handled DHCPv6 requests. A remote attacker could use this issue to cause Dnsmasq to crash, resulting in a
    denial of service, or possibly execute arbitrary code. (CVE-2017-14493)

    Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher discovered that Dnsmasq incorrectly
    handled DHCPv6 packets. A remote attacker could use this issue to possibly obtain sensitive memory
    contents. (CVE-2017-14494)

    Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher discovered that Dnsmasq incorrectly
    handled DNS requests. A remote attacker could use this issue to cause Dnsmasq to consume memory, resulting
    in a denial of service. (CVE-2017-14495)

    Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher discovered that Dnsmasq incorrectly
    handled DNS requests. A remote attacker could use this issue to cause Dnsmasq to crash, resulting in a
    denial of service. (CVE-2017-14496)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3430-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected dnsmasq, dnsmasq-base and / or dnsmasq-utils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsmasq-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2024 Canonical, Inc. / NASL script (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'dnsmasq', 'pkgver': '2.68-1ubuntu0.2'},
    {'osver': '14.04', 'pkgname': 'dnsmasq-base', 'pkgver': '2.68-1ubuntu0.2'},
    {'osver': '14.04', 'pkgname': 'dnsmasq-utils', 'pkgver': '2.68-1ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'dnsmasq', 'pkgver': '2.75-1ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'dnsmasq-base', 'pkgver': '2.75-1ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'dnsmasq-utils', 'pkgver': '2.75-1ubuntu0.16.04.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnsmasq / dnsmasq-base / dnsmasq-utils');
}
