#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2521-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81753);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-1213",
    "CVE-2015-1214",
    "CVE-2015-1215",
    "CVE-2015-1216",
    "CVE-2015-1217",
    "CVE-2015-1218",
    "CVE-2015-1219",
    "CVE-2015-1220",
    "CVE-2015-1221",
    "CVE-2015-1222",
    "CVE-2015-1223",
    "CVE-2015-1224",
    "CVE-2015-1227",
    "CVE-2015-1228",
    "CVE-2015-1229",
    "CVE-2015-1230",
    "CVE-2015-1231",
    "CVE-2015-2238"
  );
  script_bugtraq_id(72901, 72916);
  script_xref(name:"USN", value:"2521-1");

  script_name(english:"Ubuntu 14.04 LTS : Oxide vulnerabilities (USN-2521-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2521-1 advisory.

    Several out-of-bounds write bugs were discovered in Skia. If a user were tricked in to opening a specially
    crafted website, an attacker could potentially exploit these to cause a denial of service via application
    crash or execute arbitrary code with the privileges of the user invoking the program. (CVE-2015-1213,
    CVE-2015-1214, CVE-2015-1215)

    A use-after-free was discovered in the V8 bindings in Blink. If a user were tricked in to opening a
    specially crafted website, an attacker could potentially exploit this to cause a denial of service via
    renderer crash, or execute arbitrary code with the privileges of the sandboxed render process.
    (CVE-2015-1216)

    Multiple type confusion bugs were discovered in the V8 bindings in Blink. If a user were tricked in to
    opening a specially crafted website, an attacker could potentially exploit these to cause a denial of
    service via renderer crash, or execute arbitrary code with the privileges of the sandboxed render process.
    (CVE-2015-1217, CVE-2015-1230)

    Multiple use-after-free bugs were discovered in the DOM implementation in Blink. If a user were tricked in
    to opening a specially crafted website, an attacker could potentially exploit these to cause a denial of
    service via renderer crash, or execute arbitrary code with the privileges of the sandboxed render process.
    (CVE-2015-1218, CVE-2015-1223)

    An integer overflow was discovered in Skia. If a user were tricked in to opening a specially crafted
    website, an attacker could potentially exploit this to cause a denial of service via application crash or
    execute arbitrary code with the privileges of the user invoking the program. (CVE-2015-1219)

    A use-after-free was discovered in the GIF image decoder in Blink. If a user were tricked in to opening a
    specially crafted website, an attacker could potentially exploit this to cause a denial of service via
    renderer crash, or execute arbitrary code with the privileges of the sandboxed render process.
    (CVE-2015-1220)

    A use-after-free was discovered in Blink. If a user were tricked in to opening a specially crafted
    website, an attacker could potentially exploit this to cause a denial of service via renderer crash, or
    execute arbitrary code with the privileges of the sandboxed render process. (CVE-2015-1221)

    Multiple use-after-free bugs were discovered in the service worker implementation in Chromium. If a user
    were tricked in to opening a specially crafted website, an attacker could potentially exploit these to
    cause a denial of service via application crash or execute arbitrary code with the privileges of the user
    invoking the program. (CVE-2015-1222)

    An out-of-bounds read was discovered in the VPX decoder implementation in Chromium. If a user were tricked
    in to opening a specially crafted website, an attacker could potentially exploit this to cause a denial of
    service via renderer crash. (CVE-2015-1224)

    It was discovered that Blink did not initialize memory for image drawing in some circumstances. If a user
    were tricked in to opening a specially crafted website, an attacker could potentially exploit this to read
    uninitialized memory. (CVE-2015-1227)

    It was discovered that Blink did not initialize memory for a data structure in some circumstances. If a
    user were tricked in to opening a specially crafted website, an attacker could potentially exploit this to
    cause a denial of service via renderer crash, or execute arbitrary code with the privileges of the
    sandboxed render process. (CVE-2015-1228)

    It was discovered that a web proxy returning a 407 response could inject cookies in to the originally
    requested domain. If a user connected to a malicious web proxy, an attacker could potentially exploit this
    to conduct session-fixation attacks. (CVE-2015-1229)

    Multiple security issues were discovered in Chromium. If a user were tricked in to opening a specially
    crafted website, an attacker could potentially exploit these to read uninitialized memory, cause a denial
    of service via application crash or execute arbitrary code with the privileges of the user invoking the
    program. (CVE-2015-1231)

    Multiple security issues were discovered in V8. If a user were tricked in to opening a specially crafted
    website, an attacker could potentially exploit these to read uninitialized memory, cause a denial of
    service via renderer crash or execute arbitrary code with the privileges of the sandboxed render process.
    (CVE-2015-2238)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2521-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2238");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-1220");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtquick0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqmlscene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqt-qmlplugin");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'liboxideqt-qmlplugin', 'pkgver': '1.5.5-0ubuntu0.14.04.3'},
    {'osver': '14.04', 'pkgname': 'liboxideqtcore0', 'pkgver': '1.5.5-0ubuntu0.14.04.3'},
    {'osver': '14.04', 'pkgname': 'liboxideqtquick0', 'pkgver': '1.5.5-0ubuntu0.14.04.3'},
    {'osver': '14.04', 'pkgname': 'oxideqmlscene', 'pkgver': '1.5.5-0ubuntu0.14.04.3'},
    {'osver': '14.04', 'pkgname': 'oxideqt-chromedriver', 'pkgver': '1.5.5-0ubuntu0.14.04.3'},
    {'osver': '14.04', 'pkgname': 'oxideqt-codecs', 'pkgver': '1.5.5-0ubuntu0.14.04.3'},
    {'osver': '14.04', 'pkgname': 'oxideqt-codecs-extra', 'pkgver': '1.5.5-0ubuntu0.14.04.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'liboxideqt-qmlplugin / liboxideqtcore0 / liboxideqtquick0 / etc');
}
