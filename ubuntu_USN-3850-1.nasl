#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3850-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121062);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id("CVE-2018-0495", "CVE-2018-12384", "CVE-2018-12404");
  script_xref(name:"USN", value:"3850-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : NSS vulnerabilities (USN-3850-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-3850-1 advisory.

    Keegan Ryan discovered that NSS incorrectly handled ECDSA key generation. A local attacker could possibly
    use this issue to perform a cache-timing attack and recover private ECDSA keys. (CVE-2018-0495)

    It was discovered that NSS incorrectly handled certain v2-compatible ClientHello messages. A remote
    attacker could possibly use this issue to perform a replay attack. (CVE-2018-12384)

    It was discovered that NSS incorrectly handled certain padding oracles. A remote attacker could possibly
    use this issue to perform a variant of the Bleichenbacher attack. (CVE-2018-12404)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3850-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12404");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-nssdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2025 Canonical, Inc. / NASL script (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libnss3', 'pkgver': '2:3.28.4-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'libnss3-1d', 'pkgver': '2:3.28.4-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'libnss3-dev', 'pkgver': '2:3.28.4-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'libnss3-nssdb', 'pkgver': '2:3.28.4-0ubuntu0.14.04.4'},
    {'osver': '14.04', 'pkgname': 'libnss3-tools', 'pkgver': '2:3.28.4-0ubuntu0.14.04.4'},
    {'osver': '16.04', 'pkgname': 'libnss3', 'pkgver': '2:3.28.4-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'libnss3-1d', 'pkgver': '2:3.28.4-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'libnss3-dev', 'pkgver': '2:3.28.4-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'libnss3-nssdb', 'pkgver': '2:3.28.4-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'libnss3-tools', 'pkgver': '2:3.28.4-0ubuntu0.16.04.4'},
    {'osver': '18.04', 'pkgname': 'libnss3', 'pkgver': '2:3.35-2ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'libnss3-dev', 'pkgver': '2:3.35-2ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'libnss3-tools', 'pkgver': '2:3.35-2ubuntu2.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss3 / libnss3-1d / libnss3-dev / libnss3-nssdb / libnss3-tools');
}
