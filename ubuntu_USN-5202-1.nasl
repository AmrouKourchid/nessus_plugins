##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5202-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(156155);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2021-2341",
    "CVE-2021-2369",
    "CVE-2021-2388",
    "CVE-2021-35550",
    "CVE-2021-35556",
    "CVE-2021-35559",
    "CVE-2021-35561",
    "CVE-2021-35564",
    "CVE-2021-35565",
    "CVE-2021-35567",
    "CVE-2021-35578",
    "CVE-2021-35586",
    "CVE-2021-35588",
    "CVE-2021-35603"
  );
  script_xref(name:"USN", value:"5202-1");
  script_xref(name:"IAVA", value:"2021-A-0481-S");
  script_xref(name:"IAVA", value:"2021-A-0327-S");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS : OpenJDK vulnerabilities (USN-5202-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5202-1 advisory.

    Varnavas Papaioannou discovered that the FTP client implementation in OpenJDK accepted alternate server IP
    addresses when connecting with FTP passive mode. An attacker controlling an FTP server that an application
    connects to could possibly use this to expose sensitive information (rudimentary port scans). This issue
    only affected Ubuntu 16.04 ESM, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 21.04. (CVE-2021-2341)

    Markus Loewe discovered that OpenJDK did not properly handle JAR files containing multiple manifest files.
    An attacker could possibly use this to bypass JAR signature verification. This issue only affected Ubuntu
    16.04 ESM, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 21.04. (CVE-2021-2369)

    Huixin Ma discovered that the Hotspot VM in OpenJDK did not properly perform range check elimination in
    some situations. An attacker could possibly use this to construct a Java class that could bypass Java
    sandbox restrictions. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
    Ubuntu 21.04. (CVE-2021-2388)

    Asaf Greenholts discovered that OpenJDK preferred certain weak ciphers by default. An attacker could
    possibly use this to expose sensitive information. (CVE-2021-35550)

    It was discovered that the Rich Text Format (RTF) Parser in OpenJDK did not properly restrict the amount
    of memory allocated in some situations. An attacker could use this to specially craft an RTF file that
    caused a denial of service. (CVE-2021-35556)

    It was discovered that the Rich Text Format (RTF) Reader in OpenJDK did not properly restrict the amount
    of memory allocated in some situations. An attacker could use this to specially craft an RTF file that
    caused a denial of service. (CVE-2021-35559)

    Markus Loewe discovered that the HashMap and HashSet implementations in OpenJDK did not properly validate
    load factors during deserialization. An attacker could use this to cause a denial of service (excessive
    memory consumption). (CVE-2021-35561)

    It was discovered that the Keytool component in OpenJDK did not properly handle certificates with validity
    ending dates in the far future. An attacker could use this to specially craft a certificate that when
    imported could corrupt a keystore. (CVE-2021-35564)

    Tristen Hayfield discovered that the HTTP server implementation in OpenJDK did not properly handle TLS
    session close in some situations. A remote attacker could possibly use this to cause a denial of service
    (application infinite loop). (CVE-2021-35565)

    Chuck Hunley discovered that the Kerberos implementation in OpenJDK did not correctly report subject
    principals when using Kerberos Constrained Delegation. An attacker could possibly use this to cause
    incorrect Kerberos tickets to be used. (CVE-2021-35567)

    it was discovered that the TLS implementation in OpenJDK did not properly handle TLS handshakes in certain
    situations where a Java application is acting as a TLS server. A remote attacker could possibly use this
    to cause a denial of service (application crash). (CVE-2021-35578)

    it was discovered that OpenJDK did not properly restrict the amount of memory allocated when processing
    BMP images. An attacker could use this to specially craft a BMP image file that could cause a denial of
    service. (CVE-2021-35586)

    It was discovered that the HotSpot VM in OpenJDK 8 did not properly perform validation of inner class
    index values in some situations. An attacker could use this to specially craft a class file that when
    loaded could cause a denial of service (Java VM crash). (CVE-2021-35588)

    Artem Smotrakov discovered that the TLS implementation in OpenJDK used non- constant time comparisons
    during TLS handshakes. A remote attacker could use this to expose sensitive information. (CVE-2021-35603)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5202-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35550");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-demo");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u312-b07-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u312-b07-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u312-b07-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u312-b07-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u312-b07-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u312-b07-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u312-b07-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u312-b07-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.13+8-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.13+8-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.13+8-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.13+8-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.13+8-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.13+8-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.13+8-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u312-b07-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u312-b07-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u312-b07-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u312-b07-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u312-b07-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u312-b07-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u312-b07-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.13+8-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.13+8-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.13+8-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.13+8-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.13+8-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.13+8-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.13+8-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u312-b07-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u312-b07-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u312-b07-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u312-b07-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u312-b07-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u312-b07-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u312-b07-0ubuntu1~20.04', 'ubuntu_pro': FALSE}
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
    severity   : SECURITY_HOLE,
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
