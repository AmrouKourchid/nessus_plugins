#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4993-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150939);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2021-29157", "CVE-2021-33515");
  script_xref(name:"USN", value:"4993-1");

  script_name(english:"Ubuntu 20.04 LTS : Dovecot vulnerabilities (USN-4993-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4993-1 advisory.

    Kirin discovered that Dovecot incorrectly escaped kid and azp fields in JWT tokens. A local attacker could
    possibly use this issue to validate tokens using arbitrary keys. This issue only affected Ubuntu 20.10 and
    Ubuntu 21.04. (CVE-2021-29157)

    Fabian Ising and Damian Poddebniak discovered that Dovecot incorrectly handled STARTTLS when using the
    SMTP submission service. A remote attacker could possibly use this issue to inject plaintext commands
    before STARTTLS negotiation. (CVE-2021-33515)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4993-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33515");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-29157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-auth-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-lmtpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-managesieved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-sieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-submissiond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mail-stack-delivery");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'dovecot-auth-lua', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-lucene', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'dovecot-submissiond', 'pkgver': '1:2.3.7.2-1ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'mail-stack-delivery', 'pkgver': '1:2.3.7.2-1ubuntu3.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dovecot-auth-lua / dovecot-core / dovecot-dev / dovecot-gssapi / etc');
}
