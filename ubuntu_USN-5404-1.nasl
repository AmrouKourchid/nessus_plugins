##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5404-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160674);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2022-24903");
  script_xref(name:"USN", value:"5404-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Rsyslog vulnerability (USN-5404-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-5404-1 advisory.

    Pieter Agten discovered that Rsyslog incorrectly handled certain requests. An attacker could possibly use
    this issue to cause a crash.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5404-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-czmq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-hiredis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-snmp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'rsyslog', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-czmq', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-elasticsearch', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-gnutls', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-gssapi', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-hiredis', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-kafka', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-mongodb', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-mysql', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-pgsql', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '18.04', 'pkgname': 'rsyslog-relp', 'pkgver': '8.32.0-1ubuntu4.2'},
    {'osver': '20.04', 'pkgname': 'rsyslog', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-czmq', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-elasticsearch', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-gnutls', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-gssapi', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-hiredis', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-kafka', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-mongodb', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-mysql', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-openssl', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-pgsql', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'rsyslog-relp', 'pkgver': '8.2001.0-1ubuntu1.3'},
    {'osver': '22.04', 'pkgname': 'rsyslog', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-czmq', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-elasticsearch', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-gnutls', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-gssapi', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-hiredis', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-kafka', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-kubernetes', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-mongodb', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-mysql', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-openssl', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-pgsql', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-relp', 'pkgver': '8.2112.0-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'rsyslog-snmp', 'pkgver': '8.2112.0-2ubuntu2.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rsyslog / rsyslog-czmq / rsyslog-elasticsearch / rsyslog-gnutls / etc');
}
