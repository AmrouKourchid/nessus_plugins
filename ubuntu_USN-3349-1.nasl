#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3349-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101263);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-2519",
    "CVE-2016-7426",
    "CVE-2016-7427",
    "CVE-2016-7428",
    "CVE-2016-7429",
    "CVE-2016-7431",
    "CVE-2016-7433",
    "CVE-2016-7434",
    "CVE-2016-9042",
    "CVE-2016-9310",
    "CVE-2016-9311",
    "CVE-2017-6458",
    "CVE-2017-6460",
    "CVE-2017-6462",
    "CVE-2017-6463",
    "CVE-2017-6464"
  );
  script_xref(name:"USN", value:"3349-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : NTP vulnerabilities (USN-3349-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3349-1 advisory.

    Yihan Lian discovered that NTP incorrectly handled certain large request data values. A remote attacker
    could possibly use this issue to cause NTP to crash, resulting in a denial of service. This issue only
    affected Ubuntu 16.04 LTS. (CVE-2016-2519)

    Miroslav Lichvar discovered that NTP incorrectly handled certain spoofed addresses when performing rate
    limiting. A remote attacker could possibly use this issue to perform a denial of service. This issue only
    affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10. (CVE-2016-7426)

    Matthew Van Gundy discovered that NTP incorrectly handled certain crafted broadcast mode packets. A remote
    attacker could possibly use this issue to perform a denial of service. This issue only affected Ubuntu
    14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10. (CVE-2016-7427, CVE-2016-7428)

    Miroslav Lichvar discovered that NTP incorrectly handled certain responses. A remote attacker could
    possibly use this issue to perform a denial of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu
    16.04 LTS, and Ubuntu 16.10. (CVE-2016-7429)

    Sharon Goldberg and Aanchal Malhotra discovered that NTP incorrectly handled origin timestamps of zero. A
    remote attacker could possibly use this issue to bypass the origin timestamp protection mechanism. This
    issue only affected Ubuntu 16.10. (CVE-2016-7431)

    Brian Utterback, Sharon Goldberg and Aanchal Malhotra discovered that NTP incorrectly performed initial
    sync calculations. This issue only applied to Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7433)

    Magnus Stubman discovered that NTP incorrectly handled certain mrulist queries. A remote attacker could
    possibly use this issue to cause NTP to crash, resulting in a denial of service. This issue only affected
    Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7434)

    Matthew Van Gund discovered that NTP incorrectly handled origin timestamp checks. A remote attacker could
    possibly use this issue to perform a denial of service. This issue only affected Ubuntu Ubuntu 16.10, and
    Ubuntu 17.04. (CVE-2016-9042)

    Matthew Van Gundy discovered that NTP incorrectly handled certain control mode packets. A remote attacker
    could use this issue to set or unset traps. This issue only applied to Ubuntu 14.04 LTS, Ubuntu 16.04 LTS
    and Ubuntu 16.10. (CVE-2016-9310)

    Matthew Van Gundy discovered that NTP incorrectly handled the trap service. A remote attacker could
    possibly use this issue to cause NTP to crash, resulting in a denial of service. This issue only applied
    to Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-9311)

    It was discovered that NTP incorrectly handled memory when processing long variables. A remote
    authenticated user could possibly use this issue to cause NTP to crash, resulting in a denial of service.
    (CVE-2017-6458)

    It was discovered that NTP incorrectly handled memory when processing long variables. A remote
    authenticated user could possibly use this issue to cause NTP to crash, resulting in a denial of service.
    This issue only applied to Ubuntu 16.04 LTS, Ubuntu 16.10 and Ubuntu 17.04. (CVE-2017-6460)

    It was discovered that the NTP legacy DPTS refclock driver incorrectly handled the /dev/datum device. A
    local attacker could possibly use this issue to cause a denial of service. (CVE-2017-6462)

    It was discovered that NTP incorrectly handled certain invalid settings in a :config directive. A remote
    authenticated user could possibly use this issue to cause NTP to crash, resulting in a denial of service.
    (CVE-2017-6463)

    It was discovered that NTP incorrectly handled certain invalid mode configuration directives. A remote
    authenticated user could possibly use this issue to cause NTP to crash, resulting in a denial of service.
    (CVE-2017-6464)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3349-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp and / or ntpdate packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6460");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'osver': '14.04', 'pkgname': 'ntp', 'pkgver': '1:4.2.6.p5+dfsg-3ubuntu2.14.04.11'},
    {'osver': '14.04', 'pkgname': 'ntpdate', 'pkgver': '1:4.2.6.p5+dfsg-3ubuntu2.14.04.11'},
    {'osver': '16.04', 'pkgname': 'ntp', 'pkgver': '1:4.2.8p4+dfsg-3ubuntu5.5'},
    {'osver': '16.04', 'pkgname': 'ntpdate', 'pkgver': '1:4.2.8p4+dfsg-3ubuntu5.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ntp / ntpdate');
}
