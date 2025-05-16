#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3096-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93896);
  script_version("2.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-7973",
    "CVE-2015-7974",
    "CVE-2015-7975",
    "CVE-2015-7976",
    "CVE-2015-7977",
    "CVE-2015-7978",
    "CVE-2015-7979",
    "CVE-2015-8138",
    "CVE-2015-8158",
    "CVE-2016-0727",
    "CVE-2016-1547",
    "CVE-2016-1548",
    "CVE-2016-1550",
    "CVE-2016-2516",
    "CVE-2016-2518",
    "CVE-2016-4954",
    "CVE-2016-4955",
    "CVE-2016-4956"
  );
  script_xref(name:"USN", value:"3096-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : NTP vulnerabilities (USN-3096-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3096-1 advisory.

    Aanchal Malhotra discovered that NTP incorrectly handled authenticated broadcast mode. A remote attacker
    could use this issue to perform a replay attack. (CVE-2015-7973)

    Matt Street discovered that NTP incorrectly verified peer associations of symmetric keys. A remote
    attacker could use this issue to perform an impersonation attack. (CVE-2015-7974)

    Jonathan Gardner discovered that the NTP ntpq utility incorrectly handled memory. An attacker could
    possibly use this issue to cause ntpq to crash, resulting in a denial of service. This issue only affected
    Ubuntu 16.04 LTS. (CVE-2015-7975)

    Jonathan Gardner discovered that the NTP ntpq utility incorrectly handled dangerous characters in
    filenames. An attacker could possibly use this issue to overwrite arbitrary files. (CVE-2015-7976)

    Stephen Gray discovered that NTP incorrectly handled large restrict lists. An attacker could use this
    issue to cause NTP to crash, resulting in a denial of service. (CVE-2015-7977, CVE-2015-7978)

    Aanchal Malhotra discovered that NTP incorrectly handled authenticated broadcast mode. A remote attacker
    could use this issue to cause NTP to crash, resulting in a denial of service. (CVE-2015-7979)

    Jonathan Gardner discovered that NTP incorrectly handled origin timestamp checks. A remote attacker could
    use this issue to spoof peer servers. (CVE-2015-8138)

    Jonathan Gardner discovered that the NTP ntpq utility did not properly handle certain incorrect values. An
    attacker could possibly use this issue to cause ntpq to hang, resulting in a denial of service.
    (CVE-2015-8158)

    It was discovered that the NTP cronjob incorrectly cleaned up the statistics directory. A local attacker
    could possibly use this to escalate privileges. (CVE-2016-0727)

    Stephen Gray and Matthew Van Gundy discovered that NTP incorrectly validated crypto-NAKs. A remote
    attacker could possibly use this issue to prevent clients from synchronizing. (CVE-2016-1547)

    Miroslav Lichvar and Jonathan Gardner discovered that NTP incorrectly handled switching to interleaved
    symmetric mode. A remote attacker could possibly use this issue to prevent clients from synchronizing.
    (CVE-2016-1548)

    Matthew Van Gundy, Stephen Gray and Loganaden Velvindron discovered that NTP incorrectly handled message
    authentication. A remote attacker could possibly use this issue to recover the message digest key.
    (CVE-2016-1550)

    Yihan Lian discovered that NTP incorrectly handled duplicate IPs on unconfig directives. An authenticated
    remote attacker could possibly use this issue to cause NTP to crash, resulting in a denial of service.
    (CVE-2016-2516)

    Yihan Lian discovered that NTP incorrectly handled certail peer associations. A remote attacker could
    possibly use this issue to cause NTP to crash, resulting in a denial of service. (CVE-2016-2518)

    Jakub Prokes discovered that NTP incorrectly handled certain spoofed packets. A remote attacker could
    possibly use this issue to cause a denial of service. (CVE-2016-4954)

    Miroslav Lichvar discovered that NTP incorrectly handled certain packets when autokey is enabled. A remote
    attacker could possibly use this issue to cause a denial of service. (CVE-2016-4955)

    Miroslav Lichvar discovered that NTP incorrectly handled certain spoofed broadcast packets. A remote
    attacker could possibly use this issue to cause a denial of service. (CVE-2016-4956)

    In the default installation, attackers would be isolated by the NTP AppArmor profile.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3096-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp and / or ntpdate packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0727");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2024 Canonical, Inc. / NASL script (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'ntp', 'pkgver': '1:4.2.6.p5+dfsg-3ubuntu2.14.04.10'},
    {'osver': '14.04', 'pkgname': 'ntpdate', 'pkgver': '1:4.2.6.p5+dfsg-3ubuntu2.14.04.10'},
    {'osver': '16.04', 'pkgname': 'ntp', 'pkgver': '1:4.2.8p4+dfsg-3ubuntu5.3'},
    {'osver': '16.04', 'pkgname': 'ntpdate', 'pkgver': '1:4.2.8p4+dfsg-3ubuntu5.3'}
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
