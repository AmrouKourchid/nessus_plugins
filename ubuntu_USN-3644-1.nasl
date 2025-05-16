#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3644-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109723);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-2783",
    "CVE-2018-2790",
    "CVE-2018-2794",
    "CVE-2018-2795",
    "CVE-2018-2796",
    "CVE-2018-2797",
    "CVE-2018-2798",
    "CVE-2018-2799",
    "CVE-2018-2800",
    "CVE-2018-2814",
    "CVE-2018-2815"
  );
  script_xref(name:"USN", value:"3644-1");

  script_name(english:"Ubuntu 16.04 LTS : OpenJDK 8 vulnerabilities (USN-3644-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-3644-1 advisory.

    It was discovered that the Security component of OpenJDK did not correctly perform merging of multiple
    sections for the same file listed in JAR archive file manifests. An attacker could possibly use this to
    modify attributes in a manifest without invalidating the signature. (CVE-2018-2790)

    Francesco Palmarini, Marco Squarcina, Mauro Tempesta, and Riccardo Focardi discovered that the Security
    component of OpenJDK did not restrict which classes could be used when deserializing keys from the JCEKS
    key stores. An attacker could use this to specially craft a JCEKS key store to execute arbitrary code.
    (CVE-2018-2794)

    It was discovered that the Security component of OpenJDK in some situations did not properly limit the
    amount of memory allocated when performing deserialization. An attacker could use this to cause a denial
    of service (memory exhaustion). (CVE-2018-2795)

    It was discovered that the Concurrency component of OpenJDK in some situations did not properly limit the
    amount of memory allocated when performing deserialization. An attacker could use this to cause a denial
    of service (memory exhaustion). (CVE-2018-2796)

    It was discovered that the JMX component of OpenJDK in some situations did not properly limit the amount
    of memory allocated when performing deserialization. An attacker could use this to cause a denial of
    service (memory exhaustion). (CVE-2018-2797)

    It was discovered that the AWT component of OpenJDK in some situations did not properly limit the amount
    of memory allocated when performing deserialization. An attacker could use this to cause a denial of
    service (memory exhaustion). (CVE-2018-2798)

    It was discovered that the JAXP component of OpenJDK in some situations did not properly limit the amount
    of memory allocated when performing deserialization. An attacker could use this to cause a denial of
    service (memory exhaustion). (CVE-2018-2799)

    Moritz Bechler discovered that the RMI component of OpenJDK enabled HTTP transport for RMI servers by
    default. A remote attacker could use this to gain access to restricted services. (CVE-2018-2800)

    It was discovered that a vulnerability existed in the Hotspot component of OpenJDK affecting
    confidentiality, data integrity, and availability. An attacker could use this to specially craft an Java
    application that caused a denial of service or bypassed sandbox restrictions. (CVE-2018-2814)

    Apostolos Giannakidis discovered that the Serialization component of OpenJDK did not properly bound memory
    allocations in some situations. An attacker could use this to cause a denial of service (memory
    exhaustion). (CVE-2018-2815)

    David Benjamin discovered a vulnerability in the Security component of OpenJDK related to data integrity
    and confidentiality. A remote attacker could possibly use this to expose sensitive information.
    (CVE-2018-2783)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3644-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2783");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u171-b11-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u171-b11-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u171-b11-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u171-b11-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u171-b11-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u171-b11-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u171-b11-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u171-b11-0ubuntu0.16.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-8-demo / openjdk-8-jdk / openjdk-8-jdk-headless / etc');
}
