#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2459-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80471);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206"
  );
  script_bugtraq_id(
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942
  );
  script_xref(name:"USN", value:"2459-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenSSL vulnerabilities (USN-2459-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2459-1 advisory.

    Pieter Wuille discovered that OpenSSL incorrectly handled Bignum squaring. (CVE-2014-3570)

    Markus Stenberg discovered that OpenSSL incorrectly handled certain crafted DTLS messages. A remote
    attacker could use this issue to cause OpenSSL to crash, resulting in a denial of service. (CVE-2014-3571)

    Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled certain handshakes. A remote attacker
    could possibly use this issue to downgrade to ECDH, removing forward secrecy from the ciphersuite.
    (CVE-2014-3572)

    Antti Karjalainen, Tuomo Untinen and Konrad Kraszewski discovered that OpenSSL incorrectly handled certain
    certificate fingerprints. A remote attacker could possibly use this issue to trick certain applications
    that rely on the uniqueness of fingerprints. (CVE-2014-8275)

    Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled certain key exchanges. A remote attacker
    could possibly use this issue to downgrade the security of the session to EXPORT_RSA. (CVE-2015-0204)

    Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled client authentication. A remote attacker
    could possibly use this issue to authenticate without the use of a private key in certain limited
    scenarios. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-0205)

    Chris Mueller discovered that OpenSSL incorrect handled memory when processing DTLS records. A remote
    attacker could use this issue to cause OpenSSL to consume resources, resulting in a denial of service.
    This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-0206)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2459-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0205");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-0204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcrypto1.0.0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
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
    {'osver': '14.04', 'pkgname': 'libcrypto1.0.0-udeb', 'pkgver': '1.0.1f-1ubuntu2.8'},
    {'osver': '14.04', 'pkgname': 'libssl-dev', 'pkgver': '1.0.1f-1ubuntu2.8'},
    {'osver': '14.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.1f-1ubuntu2.8'},
    {'osver': '14.04', 'pkgname': 'libssl1.0.0-udeb', 'pkgver': '1.0.1f-1ubuntu2.8'},
    {'osver': '14.04', 'pkgname': 'openssl', 'pkgver': '1.0.1f-1ubuntu2.8'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcrypto1.0.0-udeb / libssl-dev / libssl1.0.0 / libssl1.0.0-udeb / etc');
}
