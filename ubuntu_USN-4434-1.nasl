#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4434-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138999);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-20839",
    "CVE-2019-20840",
    "CVE-2020-14396",
    "CVE-2020-14397",
    "CVE-2020-14398",
    "CVE-2020-14399",
    "CVE-2020-14400",
    "CVE-2020-14401",
    "CVE-2020-14402",
    "CVE-2020-14403",
    "CVE-2020-14404",
    "CVE-2020-14405"
  );
  script_xref(name:"USN", value:"4434-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : LibVNCServer vulnerabilities (USN-4434-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4434-1 advisory.

    Ramin Farajpour Cami discovered that LibVNCServer incorrectly handled certain malformed unix socket names.
    A remote attacker could exploit this with a crafted socket name, leading to a denial of service, or
    possibly execute arbitrary code. (CVE-2019-20839)

    It was discovered that LibVNCServer did not properly access byte-aligned data. A remote attacker could
    possibly use this issue to cause LibVNCServer to crash, resulting in a denial of service. This issue only
    affected Ubuntu 18.04 LTS and Ubuntu 16.04 LTS. (CVE-2019-20840)

    Christian Beier discovered that LibVNCServer incorrectly handled anonymous TLS connections. A remote
    attacker could possibly use this issue to cause LibVNCServer to crash, resulting in a denial of service.
    This issue only affected Ubuntu 20.04 LTS. (CVE-2020-14396)

    It was discovered that LibVNCServer incorrectly handled region clipping. A remote attacker could possibly
    use this issue to cause LibVNCServer to crash, resulting in a denial of service. (CVE-2020-14397)

    It was discovered that LibVNCServer did not properly reset incorrectly terminated TCP connections. A
    remote attacker could possibly use this issue to cause an infinite loop, resulting in a denial of service.
    (CVE-2020-14398)

    It was discovered that LibVNCServer did not properly access byte-aligned data. A remote attacker could
    possibly use this issue to cause LibVNCServer to crash, resulting in a denial of service. (CVE-2020-14399,
    CVE-2020-14400)

    It was discovered that LibVNCServer incorrectly handled screen scaling on the server side. A remote
    attacker could use this issue to cause LibVNCServer to crash, resulting in a denial of service, or
    possibly execute arbitrary code. (CVE-2020-14401)

    It was discovered that LibVNCServer incorrectly handled encodings. A remote attacker could use this issue
    to cause LibVNCServer to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2020-14402, CVE-2020-14403, CVE-2020-14404)

    It was discovered that LibVNCServer incorrectly handled TextChat messages. A remote attacker could
    possibly use this issue to cause LibVNCServer to crash, resulting in a denial of service. (CVE-2020-14405)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4434-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14401");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvncclient1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvncserver-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvncserver-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvncserver1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libvncclient1', 'pkgver': '0.9.10+dfsg-3ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'libvncserver-config', 'pkgver': '0.9.10+dfsg-3ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'libvncserver-dev', 'pkgver': '0.9.10+dfsg-3ubuntu0.16.04.5'},
    {'osver': '16.04', 'pkgname': 'libvncserver1', 'pkgver': '0.9.10+dfsg-3ubuntu0.16.04.5'},
    {'osver': '18.04', 'pkgname': 'libvncclient1', 'pkgver': '0.9.11+dfsg-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libvncserver-config', 'pkgver': '0.9.11+dfsg-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libvncserver-dev', 'pkgver': '0.9.11+dfsg-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libvncserver1', 'pkgver': '0.9.11+dfsg-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'libvncclient1', 'pkgver': '0.9.12+dfsg-9ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libvncserver-dev', 'pkgver': '0.9.12+dfsg-9ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libvncserver1', 'pkgver': '0.9.12+dfsg-9ubuntu0.2'}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvncclient1 / libvncserver-config / libvncserver-dev / etc');
}
