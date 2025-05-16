#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3986-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125252);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-10894",
    "CVE-2019-10895",
    "CVE-2019-10896",
    "CVE-2019-10899",
    "CVE-2019-10901",
    "CVE-2019-10903",
    "CVE-2019-9208",
    "CVE-2019-9209",
    "CVE-2019-9214"
  );
  script_xref(name:"USN", value:"3986-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Wireshark vulnerabilities (USN-3986-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3986-1 advisory.

    It was discovered that Wireshark improperly handled certain input. A remote or local attacker could cause
    Wireshark to crash by injecting malform packets onto the wire or convincing someone to read a malformed
    packet trace file.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3986-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9214");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwireshark11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwiretap8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwscodecs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwsutil9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wireshark-qt");
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
    {'osver': '16.04', 'pkgname': 'libwireshark-data', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'libwireshark-dev', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'libwireshark11', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'libwiretap-dev', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'libwiretap8', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'libwscodecs2', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'libwsutil-dev', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'libwsutil9', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'tshark', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'wireshark', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'wireshark-common', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'wireshark-dev', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'wireshark-gtk', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '16.04', 'pkgname': 'wireshark-qt', 'pkgver': '2.6.8-1~ubuntu16.04.0'},
    {'osver': '18.04', 'pkgname': 'libwireshark-data', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'libwireshark-dev', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'libwireshark11', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'libwiretap-dev', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'libwiretap8', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'libwscodecs2', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'libwsutil-dev', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'libwsutil9', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'tshark', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'wireshark', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'wireshark-common', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'wireshark-dev', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'wireshark-gtk', 'pkgver': '2.6.8-1~ubuntu18.04.0'},
    {'osver': '18.04', 'pkgname': 'wireshark-qt', 'pkgver': '2.6.8-1~ubuntu18.04.0'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwireshark-data / libwireshark-dev / libwireshark11 / etc');
}
