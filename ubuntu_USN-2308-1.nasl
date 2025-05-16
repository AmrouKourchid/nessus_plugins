#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2308-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77085);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-3505",
    "CVE-2014-3506",
    "CVE-2014-3507",
    "CVE-2014-3508",
    "CVE-2014-3509",
    "CVE-2014-3510",
    "CVE-2014-3511",
    "CVE-2014-3512",
    "CVE-2014-5139"
  );
  script_bugtraq_id(
    69075,
    69076,
    69077,
    69078,
    69079,
    69081,
    69082,
    69083,
    69084
  );
  script_xref(name:"USN", value:"2308-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenSSL vulnerabilities (USN-2308-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2308-1 advisory.

    Adam Langley and Wan-Teh Chang discovered that OpenSSL incorrectly handled certain DTLS packets. A remote
    attacker could use this issue to cause OpenSSL to crash, resulting in a denial of service. (CVE-2014-3505)

    Adam Langley discovered that OpenSSL incorrectly handled memory when processing DTLS handshake messages. A
    remote attacker could use this issue to cause OpenSSL to consume memory, resulting in a denial of service.
    (CVE-2014-3506)

    Adam Langley discovered that OpenSSL incorrectly handled memory when processing DTLS fragments. A remote
    attacker could use this issue to cause OpenSSL to leak memory, resulting in a denial of service. This
    issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3507)

    Ivan Fratric discovered that OpenSSL incorrectly leaked information in the pretty printing functions. When
    OpenSSL is used with certain applications, an attacker may use this issue to possibly gain access to
    sensitive information. (CVE-2014-3508)

    Gabor Tyukasz discovered that OpenSSL contained a race condition when processing serverhello messages. A
    malicious server could use this issue to cause clients to crash, resulting in a denial of service. This
    issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3509)

    Felix Grbert discovered that OpenSSL incorrectly handled certain DTLS handshake messages. A malicious
    server could use this issue to cause clients to crash, resulting in a denial of service. (CVE-2014-3510)

    David Benjamin and Adam Langley discovered that OpenSSL incorrectly handled fragmented ClientHello
    messages. If a remote attacker were able to perform a machine-in-the-middle attack, this flaw could be
    used to force a protocol downgrade to TLS 1.0. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04
    LTS. (CVE-2014-3511)

    Sean Devlin and Watson Ladd discovered that OpenSSL incorrectly handled certain SRP parameters. A remote
    attacker could use this with applications that use SRP to cause a denial of service, or possibly execute
    arbitrary code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3512)

    Joonas Kuorilehto and Riku Hietamki discovered that OpenSSL incorrectly handled certain Server Hello
    messages that specify an SRP ciphersuite. A malicious server could use this issue to cause clients to
    crash, resulting in a denial of service. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
    (CVE-2014-5139)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2308-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3512");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-3507");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/08");

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

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'libcrypto1.0.0-udeb', 'pkgver': '1.0.1f-1ubuntu2.5'},
    {'osver': '14.04', 'pkgname': 'libssl-dev', 'pkgver': '1.0.1f-1ubuntu2.5'},
    {'osver': '14.04', 'pkgname': 'libssl1.0.0', 'pkgver': '1.0.1f-1ubuntu2.5'},
    {'osver': '14.04', 'pkgname': 'libssl1.0.0-udeb', 'pkgver': '1.0.1f-1ubuntu2.5'},
    {'osver': '14.04', 'pkgname': 'openssl', 'pkgver': '1.0.1f-1ubuntu2.5'}
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
