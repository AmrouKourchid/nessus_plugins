#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4113-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128412);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-0197",
    "CVE-2019-10081",
    "CVE-2019-10082",
    "CVE-2019-10092",
    "CVE-2019-10097",
    "CVE-2019-10098",
    "CVE-2019-9517"
  );
  script_xref(name:"USN", value:"4113-1");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Apache HTTP Server vulnerabilities (USN-4113-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4113-1 advisory.

    Stefan Eissing discovered that the HTTP/2 implementation in Apache did not properly handle upgrade
    requests from HTTP/1.1 to HTTP/2 in some situations. A remote attacker could use this to cause a denial of
    service (daemon crash). This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.04. (CVE-2019-0197)

    Craig Young discovered that a memory overwrite error existed in Apache when performing HTTP/2 very early
    pushes in some situations. A remote attacker could use this to cause a denial of service (daemon crash).
    This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.04. (CVE-2019-10081)

    Craig Young discovered that a read-after-free error existed in the HTTP/2 implementation in Apache during
    connection shutdown. A remote attacker could use this to possibly cause a denial of service (daemon crash)
    or possibly expose sensitive information. This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.04.
    (CVE-2019-10082)

    Matei Badanoiu discovered that the mod_proxy component of Apache did not properly filter URLs when
    reporting errors in some configurations. A remote attacker could possibly use this issue to conduct cross-
    site scripting (XSS) attacks. (CVE-2019-10092)

    Daniel McCarney discovered that mod_remoteip component of Apache contained a stack buffer overflow when
    parsing headers from a trusted intermediary proxy in some situations. A remote attacker controlling a
    trusted proxy could use this to cause a denial of service or possibly execute arbitrary code. This issue
    only affected Ubuntu 19.04. (CVE-2019-10097)

    Yukitsugu Sasaki discovered that the mod_rewrite component in Apache was vulnerable to open redirects in
    some situations. A remote attacker could use this to possibly expose sensitive information or bypass
    intended restrictions. (CVE-2019-10098)

    Jonathan Looney discovered that the HTTP/2 implementation in Apache did not properly limit the amount of
    buffering for client connections in some situations. A remote attacker could use this to cause a denial of
    service (unresponsive daemon). This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.04. (CVE-2019-9517)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4113-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'apache2', 'pkgver': '2.4.18-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.18-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.18-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.18-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.18-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.18-2ubuntu3.12'},
    {'osver': '16.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.18-2ubuntu3.12'},
    {'osver': '18.04', 'pkgname': 'apache2', 'pkgver': '2.4.29-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.29-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.29-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.29-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.29-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.29-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.29-1ubuntu4.10'},
    {'osver': '18.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.29-1ubuntu4.10'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / etc');
}
