#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4796-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183156);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-7099",
    "CVE-2017-1000381",
    "CVE-2018-7160",
    "CVE-2018-7167",
    "CVE-2018-12115",
    "CVE-2018-12116",
    "CVE-2018-12122",
    "CVE-2018-12123",
    "CVE-2019-5737"
  );
  script_xref(name:"USN", value:"4796-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM : Node.js vulnerabilities (USN-4796-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4796-1 advisory.

    Alexander Minozhenko and James Bunton discovered that Node.js did not properly handle wildcards in name
    fields of X.509 TLS certificates. An attacker could use this vulnerability to execute a machine-in-the-
    middle- attack. This issue only affected Ubuntu 14.04 ESM and 16.04 ESM. (CVE-2016-7099)

    It was discovered that Node.js incorrectly handled certain NAPTR responses. A remote attacker could
    possibly use this issue to cause applications using Node.js to crash, resulting in a denial of service.
    This issue only affected Ubuntu 16.04 ESM. (CVE-2017-1000381)

    Nikita Skovoroda discovered that Node.js mishandled certain input, leading to an out of bounds write. An
    attacker could use this vulnerability to cause a denial of service (crash) or possibly execute arbitrary
    code. This issue only affected Ubuntu 18.04 ESM. (CVE-2018-12115)

    Arkadiy Tetelman discovered that Node.js improperly handled certain malformed HTTP requests. An attacker
    could use this vulnerability to inject unexpected HTTP requests. This issue only affected Ubuntu 18.04
    ESM. (CVE-2018-12116)

    Jan Maybach discovered that Node.js did not time out if incomplete HTTP/HTTPS headers were received. An
    attacker could use this vulnerability to cause a denial of service by keeping HTTP/HTTPS connections alive
    for a long period of time. This issue only affected Ubuntu 18.04 ESM. (CVE-2018-12122)

    Martin Bajanik discovered that the url.parse() method would return incorrect results if it received
    specially crafted input. An attacker could use this vulnerability to spoof the hostname and bypass
    hostname-specific security controls. This issue only affected Ubuntu 18.04 ESM. (CVE-2018-12123)

    It was discovered that Node.js is vulnerable to a DNS rebinding attack which could be exploited to perform
    remote code execution. An attack is possible from malicious websites open in a web browser with network
    access to the system running the Node.js process. This issue only affected Ubuntu 18.04 ESM.
    (CVE-2018-7160)

    It was discovered that the Buffer.fill() and Buffer.alloc() methods improperly handled certain inputs. An
    attacker could use this vulnerability to cause a denial of service. This issue only affected Ubuntu 18.04
    ESM. (CVE-2018-7167)

    Marco Pracucci discovered that Node.js mishandled HTTP and HTTPS connections. An attacker could use this
    vulnerability to cause a denial of service. This issue only affected Ubuntu 18.04 ESM. (CVE-2019-5737)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4796-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs, nodejs-dev and / or nodejs-legacy packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nodejs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nodejs-legacy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
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
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'nodejs', 'pkgver': '4.2.6~dfsg-1ubuntu4.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nodejs-dev', 'pkgver': '4.2.6~dfsg-1ubuntu4.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nodejs-legacy', 'pkgver': '4.2.6~dfsg-1ubuntu4.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'nodejs', 'pkgver': '8.10.0~dfsg-2ubuntu0.4+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'nodejs-dev', 'pkgver': '8.10.0~dfsg-2ubuntu0.4+esm1', 'ubuntu_pro': TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-dev / nodejs-legacy');
}
