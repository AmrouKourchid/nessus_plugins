#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4223-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132240);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-2894",
    "CVE-2019-2945",
    "CVE-2019-2949",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2977",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2987",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2999"
  );
  script_xref(name:"USN", value:"4223-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : OpenJDK vulnerabilities (USN-4223-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4223-1 advisory.

    Jan Jancar, Petr Svenda, and Vladimir Sedlacek discovered that a side- channel vulnerability existed in
    the ECDSA implementation in OpenJDK. An Attacker could use this to expose sensitive information.
    (CVE-2019-2894)

    It was discovered that the Socket implementation in OpenJDK did not properly restrict the creation of
    subclasses with a custom Socket implementation. An attacker could use this to specially create a Java
    class that could possibly bypass Java sandbox restrictions. (CVE-2019-2945)

    Rob Hamm discovered that the Kerberos implementation in OpenJDK did not properly handle proxy credentials.
    An attacker could possibly use this to impersonate another user. (CVE-2019-2949)

    It was discovered that a NULL pointer dereference existed in the font handling implementation in OpenJDK.
    An attacker could use this to cause a denial of service (application crash). (CVE-2019-2962)

    It was discovered that the Concurrency subsystem in OpenJDK did not properly bound stack consumption when
    compiling regular expressions. An attacker could use this to cause a denial of service (application
    crash). (CVE-2019-2964)

    It was discovered that the JAXP subsystem in OpenJDK did not properly handle XPath expressions in some
    situations. An attacker could use this to cause a denial of service (application crash). (CVE-2019-2973,
    CVE-2019-2981)

    It was discovered that the Nashorn JavaScript subcomponent in OpenJDK did not properly handle regular
    expressions in some situations. An attacker could use this to cause a denial of service (application
    crash). (CVE-2019-2975)

    It was discovered that the String class in OpenJDK contained an out-of- bounds access vulnerability. An
    attacker could use this to cause a denial of service (application crash) or possibly expose sensitive
    information. This issue only affected OpenJDK 11 in Ubuntu 18.04 LTS, Ubuntu 19.04, and Ubuntu 19.10.
    (CVE-2019-2977)

    It was discovered that the Jar URL handler in OpenJDK did not properly handled nested Jar URLs in some
    situations. An attacker could use this to cause a denial of service (application crash). (CVE-2019-2978)

    It was discovered that the Serialization component of OpenJDK did not properly handle deserialization of
    certain object attributes. An attacker could use this to cause a denial of service (application crash).
    (CVE-2019-2983)

    It was discovered that the FreetypeFontScaler class in OpenJDK did not properly validate dimensions of
    glyph bitmap images read from font files. An attacker could specially craft a font file that could cause a
    denial of service (application crash). (CVE-2019-2987)

    It was discovered that a buffer overflow existed in the SunGraphics2D class in OpenJDK. An attacker could
    possibly use this to cause a denial of service (excessive memory consumption or application crash).
    (CVE-2019-2988)

    It was discovered that the Networking component in OpenJDK did not properly handle certain responses from
    HTTP proxies. An attacker controlling a malicious HTTP proxy could possibly use this to inject content
    into a proxied HTTP connection. (CVE-2019-2989)

    It was discovered that the font handling implementation in OpenJDK did not properly validate TrueType font
    files in some situations. An attacker could specially craft a font file that could cause a denial of
    service (excessive memory consumption). (CVE-2019-2992)

    It was discovered that the JavaDoc generator in OpenJDK did not properly filter out some HTML elements
    properly, including documentation comments in Java source code. An attacker could possibly use this to
    craft a Cross-Site Scripting attack. (CVE-2019-2999)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4223-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2977");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-demo");
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
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u232-b09-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u232-b09-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u232-b09-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u232-b09-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u232-b09-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u232-b09-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u232-b09-0ubuntu1~16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u232-b09-0ubuntu1~16.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.5+10-0ubuntu1.1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.5+10-0ubuntu1.1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.5+10-0ubuntu1.1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.5+10-0ubuntu1.1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.5+10-0ubuntu1.1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.5+10-0ubuntu1.1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.5+10-0ubuntu1.1~18.04'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-11-demo / openjdk-11-jdk / openjdk-11-jdk-headless / etc');
}
