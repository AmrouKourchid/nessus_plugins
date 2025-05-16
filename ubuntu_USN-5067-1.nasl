#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5067-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153144);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-10852",
    "CVE-2018-16838",
    "CVE-2019-3811",
    "CVE-2021-3621"
  );
  script_xref(name:"USN", value:"5067-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : SSSD vulnerabilities (USN-5067-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5067-1 advisory.

    Jakub Hrozek discovered that SSSD incorrectly handled file permissions. A local attacker could possibly
    use this issue to read the sudo rules available for any user. This issue only affected Ubuntu 18.04 LTS.
    (CVE-2018-10852)

    It was discovered that SSSD incorrectly handled Group Policy Objects. When SSSD is configured with too
    strict permissions causing the GPO to not be readable, SSSD will allow all authenticated users to login
    instead of being denied, contrary to expectations. This issue only affected Ubuntu 18.04 LTS.
    (CVE-2018-16838)

    It was discovered that SSSD incorrectly handled users with no home directory set. When no home directory
    was set, SSSD would return the root directory instead of an empty string, possibly bypassing security
    measures. This issue only affected Ubuntu 18.04 LTS. (CVE-2019-3811)

    Cedric Buissart discovered that SSSD incorrectly handled the sssctl command. In certain environments, a
    local user could use this issue to execute arbitrary commands and possibly escalate privileges.
    (CVE-2021-3621)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5067-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libipa-hbac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libipa-hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-certmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-certmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-nss-idmap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-nss-idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-simpleifp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsss-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient-sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient-sssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libipa-hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libsss-nss-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-libipa-hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-libsss-nss-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-ad-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-tools");
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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libipa-hbac-dev', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libipa-hbac0', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libnss-sss', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libpam-sss', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-certmap-dev', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-certmap0', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-idmap-dev', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-idmap0', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-nss-idmap-dev', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-nss-idmap0', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-simpleifp-dev', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-simpleifp0', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libsss-sudo', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libwbclient-sssd', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'libwbclient-sssd-dev', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'python-libipa-hbac', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'python-libsss-nss-idmap', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'python-sss', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'python3-libipa-hbac', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'python3-libsss-nss-idmap', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'python3-sss', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-ad', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-ad-common', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-common', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-dbus', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-ipa', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-kcm', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-krb5', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-krb5-common', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-ldap', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-proxy', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'sssd-tools', 'pkgver': '1.16.1-1ubuntu1.8'},
    {'osver': '20.04', 'pkgname': 'libipa-hbac-dev', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libipa-hbac0', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libnss-sss', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libpam-sss', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-certmap-dev', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-certmap0', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-idmap-dev', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-idmap0', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-nss-idmap-dev', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-nss-idmap0', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-simpleifp-dev', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-simpleifp0', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libsss-sudo', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libwbclient-sssd', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'libwbclient-sssd-dev', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'python3-libipa-hbac', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'python3-libsss-nss-idmap', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'python3-sss', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-ad', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-ad-common', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-common', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-dbus', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-ipa', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-kcm', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-krb5', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-krb5-common', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-ldap', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-proxy', 'pkgver': '2.2.3-3ubuntu0.7'},
    {'osver': '20.04', 'pkgname': 'sssd-tools', 'pkgver': '2.2.3-3ubuntu0.7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa-hbac-dev / libipa-hbac0 / libnss-sss / libpam-sss / etc');
}
