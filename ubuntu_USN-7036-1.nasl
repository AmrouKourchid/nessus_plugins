#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7036-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207797);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2022-30122",
    "CVE-2022-30123",
    "CVE-2022-44570",
    "CVE-2022-44571",
    "CVE-2022-44572",
    "CVE-2023-27530",
    "CVE-2023-27539",
    "CVE-2024-25126",
    "CVE-2024-26141",
    "CVE-2024-26146"
  );
  script_xref(name:"USN", value:"7036-1");

  script_name(english:"Ubuntu 22.04 LTS : Rack vulnerabilities (USN-7036-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7036-1 advisory.

    It was discovered that Rack was not properly parsing data when processing multipart POST requests. If a
    user or automated system were tricked into sending a specially crafted multipart POST request to an
    application using Rack, a remote attacker could possibly use this issue to cause a denial of service.
    (CVE-2022-30122)

    It was discovered that Rack was not properly escaping untrusted data when performing logging operations,
    which could cause shell escaped sequences to be written to a terminal. If a user or automated system were
    tricked into sending a specially crafted request to an application using Rack, a remote attacker could
    possibly use this issue to execute arbitrary code in the machine running the application. (CVE-2022-30123)

    It was discovered that Rack did not properly structure regular expressions in some of its parsing
    components, which could result in uncontrolled resource consumption if an application using Rack received
    specially crafted input. A remote attacker could possibly use this issue to cause a denial of service.
    (CVE-2022-44570, CVE-2022-44571)

    It was discovered that Rack did not properly structure regular expressions in its multipart parsing
    component, which could result in uncontrolled resource consumption if an application using Rack to parse
    multipart posts received specially crafted input. A remote attacker could possibly use this issue to cause
    a denial of service. (CVE-2022-44572)

    It was discovered that Rack incorrectly handled Multipart MIME parsing. A remote attacker could possibly
    use this issue to cause Rack to consume resources, leading to a denial of service. (CVE-2023-27530)

    It was discovered that Rack incorrectly handled certain regular expressions. A remote attacker could
    possibly use this issue to cause Rack to consume resources, leading to a denial of service.
    (CVE-2023-27539)

    It was discovered that Rack incorrectly parsed certain media types. A remote attacker could possibly use
    this issue to cause Rack to consume resources, leading to a denial of service. (CVE-2024-25126)

    It was discovered that Rack incorrectly handled certain Range headers. A remote attacker could possibly
    use this issue to cause Rack to create large responses, leading to a denial of service. (CVE-2024-26141)

    It was discovered that Rack incorrectly handled certain crafted headers. A remote attacker could possibly
    use this issue to cause Rack to consume resources, leading to a denial of service. (CVE-2024-26146)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7036-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby-rack package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30123");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby-rack");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'ruby-rack', 'pkgver': '2.1.4-5ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby-rack');
}
