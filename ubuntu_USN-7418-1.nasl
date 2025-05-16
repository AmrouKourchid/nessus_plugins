#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7418-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233968);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/07");

  script_cve_id(
    "CVE-2024-35176",
    "CVE-2024-39908",
    "CVE-2024-41123",
    "CVE-2024-43398",
    "CVE-2025-25186",
    "CVE-2025-27219",
    "CVE-2025-27220",
    "CVE-2025-27221"
  );
  script_xref(name:"USN", value:"7418-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : Ruby vulnerabilities (USN-7418-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7418-1 advisory.

    It was discovered that Ruby incorrectly handled parsing of an XML document that has specific XML
    characters in an attribute value using REXML gem. An attacker could use this issue to cause Ruby to crash,
    resulting in a denial of service. This issue only affected in Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and
    Ubuntu 24.10. (CVE-2024-35176, CVE-2024-39908, CVE-2024-41123, CVE-2024-43398)

    It was discovered that Ruby incorrectly handled expanding ranges in the net-imap response parser. If a
    user or automated system were tricked into connecting to a malicious IMAP server, a remote attacker could
    possibly use this issue to consume memory, leading to a denial of service. This issue only affected Ubuntu
    24.04 LTS, and Ubuntu 24.10. (CVE-2025-25186)

    It was discovered that the Ruby CGI gem incorrectly handled parsing certain cookies. A remote attacker
    could possibly use this issue to consume resources, leading to a denial of service. (CVE-2025-27219)

    It was discovered that the Ruby CGI gem incorrectly handled parsing certain regular expressions. A remote
    attacker could possibly use this issue to consume resources, leading to a denial of service.
    (CVE-2025-27220)

    It was discovered that the Ruby URI gem incorrectly handled certain URI handling methods. A remote
    attacker could possibly use this issue to leak authentication credentials. (CVE-2025-27221)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7418-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby3.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby3.3-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libruby2.7', 'pkgver': '2.7.0-5ubuntu1.18'},
    {'osver': '20.04', 'pkgname': 'ruby2.7', 'pkgver': '2.7.0-5ubuntu1.18'},
    {'osver': '20.04', 'pkgname': 'ruby2.7-dev', 'pkgver': '2.7.0-5ubuntu1.18'},
    {'osver': '22.04', 'pkgname': 'libruby3.0', 'pkgver': '3.0.2-7ubuntu2.10'},
    {'osver': '22.04', 'pkgname': 'ruby3.0', 'pkgver': '3.0.2-7ubuntu2.10'},
    {'osver': '22.04', 'pkgname': 'ruby3.0-dev', 'pkgver': '3.0.2-7ubuntu2.10'},
    {'osver': '24.04', 'pkgname': 'libruby3.2', 'pkgver': '3.2.3-1ubuntu0.24.04.5'},
    {'osver': '24.04', 'pkgname': 'ruby3.2', 'pkgver': '3.2.3-1ubuntu0.24.04.5'},
    {'osver': '24.04', 'pkgname': 'ruby3.2-dev', 'pkgver': '3.2.3-1ubuntu0.24.04.5'},
    {'osver': '24.10', 'pkgname': 'libruby3.3', 'pkgver': '3.3.4-2ubuntu5.2'},
    {'osver': '24.10', 'pkgname': 'ruby3.3', 'pkgver': '3.3.4-2ubuntu5.2'},
    {'osver': '24.10', 'pkgname': 'ruby3.3-dev', 'pkgver': '3.3.4-2ubuntu5.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libruby2.7 / libruby3.0 / libruby3.2 / libruby3.3 / ruby2.7 / etc');
}
