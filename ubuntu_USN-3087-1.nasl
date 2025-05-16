#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3087-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93684);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6306"
  );
  script_xref(name:"USN", value:"3087-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : OpenSSL vulnerabilities (USN-3087-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3087-1 advisory.

    Shi Lei discovered that OpenSSL incorrectly handled the OCSP Status Request extension. A remote attacker
    could possibly use this issue to cause memory consumption, resulting in a denial of service.
    (CVE-2016-6304)

    Guido Vranken discovered that OpenSSL used undefined behaviour when performing pointer arithmetic. A
    remote attacker could possibly use this issue to cause OpenSSL to crash, resulting in a denial of service.
    This issue has only been addressed in Ubuntu 16.04 LTS in this update. (CVE-2016-2177)

    Csar Pereida, Billy Brumley, and Yuval Yarom discovered that OpenSSL did not properly use constant-time
    operations when performing DSA signing. A remote attacker could possibly use this issue to perform a
    cache-timing attack and recover private DSA keys. (CVE-2016-2178)

    Quan Luo discovered that OpenSSL did not properly restrict the lifetime of queue entries in the DTLS
    implementation. A remote attacker could possibly use this issue to consume memory, resulting in a denial
    of service. (CVE-2016-2179)

    Shi Lei discovered that OpenSSL incorrectly handled memory in the TS_OBJ_print_bio() function. A remote
    attacker could possibly use this issue to cause a denial of service. (CVE-2016-2180)

    It was discovered that the OpenSSL incorrectly handled the DTLS anti-replay feature. A remote attacker
    could possibly use this issue to cause a denial of service. (CVE-2016-2181)

    Shi Lei discovered that OpenSSL incorrectly validated division results. A remote attacker could possibly
    use this issue to cause a denial of service. (CVE-2016-2182)

    Karthik Bhargavan and Gaetan Leurent discovered that the DES and Triple DES ciphers were vulnerable to
    birthday attacks. A remote attacker could possibly use this flaw to obtain clear text data from long
    encrypted sessions. This update moves DES from the HIGH cipher list to MEDIUM. (CVE-2016-2183)

    Shi Lei discovered that OpenSSL incorrectly handled certain ticket lengths. A remote attacker could use
    this issue to cause a denial of service. (CVE-2016-6302)

    Shi Lei discovered that OpenSSL incorrectly handled memory in the MDC2_Update() function. A remote
    attacker could possibly use this issue to cause a denial of service. (CVE-2016-6303)

    Shi Lei discovered that OpenSSL incorrectly performed certain message length checks. A remote attacker
    could possibly use this issue to cause a denial of service. (CVE-2016-6306)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3087-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6303");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrypto1.0.0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
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
    {'osver': '14.04', 'pkgname': 'libcrypto1.0.0-udeb', 'pkgver': '1.0.1f-1ubuntu2.20'},
    {'osver': '14.04', 'pkgname': 'libssl-dev', 'pkgver': '1.0.1f-1ubuntu2.20'},
    {'osver': '14.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.1f-1ubuntu2.20'},
    {'osver': '14.04', 'pkgname': 'libssl1.0.0-udeb', 'pkgver': '1.0.1f-1ubuntu2.20'},
    {'osver': '14.04', 'pkgname': 'openssl', 'pkgver': '1.0.1f-1ubuntu2.20'},
    {'osver': '16.04', 'pkgname': 'libcrypto1.0.0-udeb', 'pkgver': '1.0.2g-1ubuntu4.4'},
    {'osver': '16.04', 'pkgname': 'libssl-dev', 'pkgver': '1.0.2g-1ubuntu4.4'},
    {'osver': '16.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.2g-1ubuntu4.4'},
    {'osver': '16.04', 'pkgname': 'libssl1.0.0-udeb', 'pkgver': '1.0.2g-1ubuntu4.4'},
    {'osver': '16.04', 'pkgname': 'openssl', 'pkgver': '1.0.2g-1ubuntu4.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcrypto1.0.0-udeb / libssl-dev / libssl1.0.0 / libssl1.0.0-udeb / etc');
}
