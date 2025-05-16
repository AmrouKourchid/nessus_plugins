#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3614-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108794);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-2579",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2602",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2629",
    "CVE-2018-2633",
    "CVE-2018-2634",
    "CVE-2018-2637",
    "CVE-2018-2641",
    "CVE-2018-2663",
    "CVE-2018-2677",
    "CVE-2018-2678"
  );
  script_xref(name:"USN", value:"3614-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenJDK 7 vulnerabilities (USN-3614-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-3614-1 advisory.

    It was discovered that a race condition existed in the cryptography implementation in OpenJDK. An attacker
    could possibly use this to expose sensitive information. (CVE-2018-2579)

    It was discovered that the LDAP implementation in OpenJDK did not properly encode login names. A remote
    attacker could possibly use this to expose sensitive information. (CVE-2018-2588)

    It was discovered that the DNS client implementation in OpenJDK did not properly randomize source ports. A
    remote attacker could use this to spoof responses to DNS queries made by Java applications.
    (CVE-2018-2599)

    It was discovered that the Internationalization component of OpenJDK did not restrict search paths when
    loading resource bundle classes. A local attacker could use this to trick a user into running malicious
    code. (CVE-2018-2602)

    It was discovered that OpenJDK did not properly restrict memory allocations when parsing DER input. A
    remote attacker could possibly use this to cause a denial of service. (CVE-2018-2603)

    It was discovered that the Java Cryptography Extension (JCE) implementation in OpenJDK in some situations
    did not guarantee sufficient strength of keys during key agreement. An attacker could use this to expose
    sensitive information. (CVE-2018-2618)

    It was discovered that the Java GSS implementation in OpenJDK in some situations did not properly handle
    GSS contexts in the native GSS library. An attacker could possibly use this to access unauthorized
    resources. (CVE-2018-2629)

    It was discovered that the LDAP implementation in OpenJDK did not properly handle LDAP referrals in some
    situations. An attacker could possibly use this to expose sensitive information or gain unauthorized
    privileges. (CVE-2018-2633)

    It was discovered that the Java GSS implementation in OpenJDK in some situations did not properly apply
    subject credentials. An attacker could possibly use this to expose sensitive information or gain access to
    unauthorized resources. (CVE-2018-2634)

    It was discovered that the Java Management Extensions (JMX) component of OpenJDK did not properly apply
    deserialization filters in some situations. An attacker could use this to bypass deserialization
    restrictions. (CVE-2018-2637)

    It was discovered that a use-after-free vulnerability existed in the AWT component of OpenJDK when loading
    the GTK library. An attacker could possibly use this to execute arbitrary code and escape Java sandbox
    restrictions. (CVE-2018-2641)

    It was discovered that in some situations OpenJDK did not properly validate objects when performing
    deserialization. An attacker could use this to cause a denial of service (application crash or excessive
    memory consumption). (CVE-2018-2663)

    It was discovered that the AWT component of OpenJDK did not properly restrict the amount of memory
    allocated when deserializing some objects. An attacker could use this to cause a denial of service
    (excessive memory consumption). (CVE-2018-2677)

    It was discovered that the JNDI component of OpenJDK did not properly restrict the amount of memory
    allocated when deserializing objects in some situations. An attacker could use this to cause a denial of
    service (excessive memory consumption). (CVE-2018-2678)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3614-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2637");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2633");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2018-2024 Canonical, Inc. / NASL script (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'icedtea-7-jre-jamvm', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-demo', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jdk', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-headless', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-lib', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-jre-zero', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-source', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'},
    {'osver': '14.04', 'pkgname': 'openjdk-7-tests', 'pkgver': '7u171-2.6.13-0ubuntu0.14.04.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'icedtea-7-jre-jamvm / openjdk-7-demo / openjdk-7-jdk / etc');
}
