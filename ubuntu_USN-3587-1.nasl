#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3587-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(107147);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2017-14461", "CVE-2017-15130");
  script_xref(name:"USN", value:"3587-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Dovecot vulnerabilities (USN-3587-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3587-1 advisory.

    It was discovered that Dovecot incorrectly handled parsing certain email addresses. A remote attacker
    could use this issue to cause Dovecot to crash, resulting in a denial of service, or possibly obtain
    sensitive information. (CVE-2017-14461)

    It was discovered that Dovecot incorrectly handled TLS SNI config lookups. A remote attacker could
    possibly use this issue to cause Dovecot to crash, resulting in a denial of service. (CVE-2017-15130)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3587-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mail-stack-delivery");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
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
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '14.04', 'pkgname': 'mail-stack-delivery', 'pkgver': '1:2.2.9-1ubuntu2.4'},
    {'osver': '16.04', 'pkgname': 'dovecot-core', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-dev', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-gssapi', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-imapd', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-ldap', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-lmtpd', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-lucene', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-managesieved', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-mysql', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-pgsql', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-pop3d', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-sieve', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-solr', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'dovecot-sqlite', 'pkgver': '1:2.2.22-1ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'mail-stack-delivery', 'pkgver': '1:2.2.22-1ubuntu2.7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dovecot-core / dovecot-dev / dovecot-gssapi / dovecot-imapd / etc');
}
