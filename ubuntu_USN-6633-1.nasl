#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6633-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190450);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2023-4408",
    "CVE-2023-5517",
    "CVE-2023-5679",
    "CVE-2023-50387",
    "CVE-2023-50868"
  );
  script_xref(name:"USN", value:"6633-1");
  script_xref(name:"IAVA", value:"2024-A-0103-S");

  script_name(english:"Ubuntu 22.04 LTS / 23.10 : Bind vulnerabilities (USN-6633-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 23.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6633-1 advisory.

    Shoham Danino, Anat Bremler-Barr, Yehuda Afek, and Yuval Shavitt discovered that Bind incorrectly handled
    parsing large DNS messages. A remote attacker could possibly use this issue to cause Bind to consume
    resources, leading to a denial of service. (CVE-2023-4408)

    Elias Heftrig, Haya Schulmann, Niklas Vogel, and Michael Waidner discovered that Bind icorrectly handled
    validating DNSSEC messages. A remote attacker could possibly use this issue to cause Bind to consume
    resources, leading to a denial of service. (CVE-2023-50387)

    It was discovered that Bind incorrectly handled preparing an NSEC3 closest encloser proof. A remote
    attacker could possibly use this issue to cause Bind to consume resources, leading to a denial of service.
    (CVE-2023-50868)

    It was discovered that Bind incorrectly handled reverse zone queries when nxdomain-redirect is enabled. A
    remote attacker could possibly use this issue to cause Bind to crash, leading to a denial of service.
    (CVE-2023-5517)

    It was discovered that Bind incorrectly handled recursive resolution when both DNS64 and serve-stable were
    enabled. A remote attacker could possibly use this issue to cause Bind to crash, leading to a denial of
    service. (CVE-2023-5679)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6633-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5517");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'bind9', 'pkgver': '1:9.18.18-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-dev', 'pkgver': '1:9.18.18-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.18.18-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.18.18-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-libs', 'pkgver': '1:9.18.18-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9-utils', 'pkgver': '1:9.18.18-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.18.18-0ubuntu0.22.04.2'},
    {'osver': '22.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.18.18-0ubuntu0.22.04.2'},
    {'osver': '23.10', 'pkgname': 'bind9', 'pkgver': '1:9.18.18-0ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'bind9-dev', 'pkgver': '1:9.18.18-0ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.18.18-0ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'bind9-host', 'pkgver': '1:9.18.18-0ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'bind9-libs', 'pkgver': '1:9.18.18-0ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'bind9-utils', 'pkgver': '1:9.18.18-0ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'bind9utils', 'pkgver': '1:9.18.18-0ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'dnsutils', 'pkgver': '1:9.18.18-0ubuntu2.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-dev / bind9-dnsutils / bind9-host / bind9-libs / etc');
}
