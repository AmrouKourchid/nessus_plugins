#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2783-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86630);
  script_version("2.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-5146",
    "CVE-2015-5194",
    "CVE-2015-5195",
    "CVE-2015-5196",
    "CVE-2015-5219",
    "CVE-2015-5300",
    "CVE-2015-7691",
    "CVE-2015-7692",
    "CVE-2015-7701",
    "CVE-2015-7702",
    "CVE-2015-7703",
    "CVE-2015-7704",
    "CVE-2015-7705",
    "CVE-2015-7850",
    "CVE-2015-7852",
    "CVE-2015-7853",
    "CVE-2015-7855",
    "CVE-2015-7871"
  );
  script_xref(name:"TRA", value:"TRA-2015-04");
  script_xref(name:"USN", value:"2783-1");

  script_name(english:"Ubuntu 14.04 LTS : NTP vulnerabilities (USN-2783-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2783-1 advisory.

    Aleksis Kauppinen discovered that NTP incorrectly handled certain remote config packets. In a non-default
    configuration, a remote authenticated attacker could possibly use this issue to cause NTP to crash,
    resulting in a denial of service. (CVE-2015-5146)

    Miroslav Lichvar discovered that NTP incorrectly handled logconfig directives. In a non-default
    configuration, a remote authenticated attacker could possibly use this issue to cause NTP to crash,
    resulting in a denial of service. (CVE-2015-5194)

    Miroslav Lichvar discovered that NTP incorrectly handled certain statistics types. In a non-default
    configuration, a remote authenticated attacker could possibly use this issue to cause NTP to crash,
    resulting in a denial of service. (CVE-2015-5195)

    Miroslav Lichvar discovered that NTP incorrectly handled certain file paths. In a non-default
    configuration, a remote authenticated attacker could possibly use this issue to cause NTP to crash,
    resulting in a denial of service, or overwrite certain files. (CVE-2015-5196, CVE-2015-7703)

    Miroslav Lichvar discovered that NTP incorrectly handled certain packets. A remote attacker could possibly
    use this issue to cause NTP to hang, resulting in a denial of service. (CVE-2015-5219)

    Aanchal Malhotra, Isaac E. Cohen, and Sharon Goldberg discovered that NTP incorrectly handled restarting
    after hitting a panic threshold. A remote attacker could possibly use this issue to alter the system time
    on clients. (CVE-2015-5300)

    It was discovered that NTP incorrectly handled autokey data packets. A remote attacker could possibly use
    this issue to cause NTP to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2015-7691, CVE-2015-7692, CVE-2015-7702)

    It was discovered that NTP incorrectly handled memory when processing certain autokey messages. A remote
    attacker could possibly use this issue to cause NTP to consume memory, resulting in a denial of service.
    (CVE-2015-7701)

    Aanchal Malhotra, Isaac E. Cohen, and Sharon Goldberg discovered that NTP incorrectly handled rate
    limiting. A remote attacker could possibly use this issue to cause clients to stop updating their clock.
    (CVE-2015-7704, CVE-2015-7705)

    Yves Younan discovered that NTP incorrectly handled logfile and keyfile directives. In a non-default
    configuration, a remote authenticated attacker could possibly use this issue to cause NTP to enter a loop,
    resulting in a denial of service. (CVE-2015-7850)

    Yves Younan and Aleksander Nikolich discovered that NTP incorrectly handled ascii conversion. A remote
    attacker could possibly use this issue to cause NTP to crash, resulting in a denial of service, or
    possibly execute arbitrary code. (CVE-2015-7852)

    Yves Younan discovered that NTP incorrectly handled reference clock memory. A malicious refclock could
    possibly use this issue to cause NTP to crash, resulting in a denial of service, or possibly execute
    arbitrary code. (CVE-2015-7853)

    John D Doug Birdwell discovered that NTP incorrectly handled decoding certain bogus values. An attacker
    could possibly use this issue to cause NTP to crash, resulting in a denial of service. (CVE-2015-7855)

    Stephen Gray discovered that NTP incorrectly handled symmetric association authentication. A remote
    attacker could use this issue to possibly bypass authentication and alter the system clock.
    (CVE-2015-7871)

    In the default installation, attackers would be isolated by the NTP AppArmor profile.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2783-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp and / or ntpdate packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2024 Canonical, Inc. / NASL script (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'ntp', 'pkgver': '1:4.2.6.p5+dfsg-3ubuntu2.14.04.5'},
    {'osver': '14.04', 'pkgname': 'ntpdate', 'pkgver': '1:4.2.6.p5+dfsg-3ubuntu2.14.04.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ntp / ntpdate');
}
