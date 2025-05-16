#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6836-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200669);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2023-3758");
  script_xref(name:"USN", value:"6836-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS : SSSD vulnerability (USN-6836-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS host has packages installed that are affected by a
vulnerability as referenced in the USN-6836-1 advisory.

    It was discovered that SSSD did not always correctly apply the GPO policy for authenticated users,
    contrary to expectations. This could result in improper authorization or improper access to resources.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6836-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libipa-hbac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libipa-hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libipa-hbac0t64");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-libipa-hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-libsss-nss-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-ad-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-idp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-passkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sssd-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.10 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libipa-hbac-dev', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libipa-hbac0', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libnss-sss', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libpam-sss', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-certmap-dev', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-certmap0', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-idmap-dev', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-idmap0', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-nss-idmap-dev', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-nss-idmap0', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-simpleifp-dev', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-simpleifp0', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libsss-sudo', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libwbclient-sssd', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'libwbclient-sssd-dev', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'python3-libipa-hbac', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'python3-libsss-nss-idmap', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'python3-sss', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-ad', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-ad-common', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-common', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-dbus', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-ipa', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-kcm', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-krb5', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-krb5-common', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-ldap', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-proxy', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '20.04', 'pkgname': 'sssd-tools', 'pkgver': '2.2.3-3ubuntu0.13'},
    {'osver': '22.04', 'pkgname': 'libipa-hbac-dev', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libipa-hbac0', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libnss-sss', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libpam-sss', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-certmap-dev', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-certmap0', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-idmap-dev', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-idmap0', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-nss-idmap-dev', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-nss-idmap0', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-simpleifp-dev', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-simpleifp0', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsss-sudo', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'python3-libipa-hbac', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'python3-libsss-nss-idmap', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'python3-sss', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-ad', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-ad-common', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-common', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-dbus', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-ipa', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-kcm', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-krb5', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-krb5-common', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-ldap', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-proxy', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'sssd-tools', 'pkgver': '2.6.3-1ubuntu3.3'},
    {'osver': '23.10', 'pkgname': 'libipa-hbac-dev', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libipa-hbac0', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libnss-sss', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libpam-sss', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsss-certmap-dev', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsss-certmap0', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsss-idmap-dev', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsss-idmap0', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsss-nss-idmap-dev', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsss-nss-idmap0', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsss-sudo', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'python3-libipa-hbac', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'python3-libsss-nss-idmap', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'python3-sss', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-ad', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-ad-common', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-common', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-dbus', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-idp', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-ipa', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-kcm', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-krb5', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-krb5-common', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-ldap', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-passkey', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-proxy', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'sssd-tools', 'pkgver': '2.9.1-2ubuntu2.1'},
    {'osver': '24.04', 'pkgname': 'libipa-hbac-dev', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libipa-hbac0t64', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libnss-sss', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libpam-sss', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libsss-certmap-dev', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libsss-certmap0', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libsss-idmap-dev', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libsss-idmap0', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libsss-nss-idmap-dev', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libsss-nss-idmap0', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'libsss-sudo', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'python3-libipa-hbac', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'python3-libsss-nss-idmap', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'python3-sss', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-ad', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-ad-common', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-common', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-dbus', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-idp', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-ipa', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-kcm', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-krb5', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-krb5-common', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-ldap', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-passkey', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-proxy', 'pkgver': '2.9.4-1.1ubuntu6.1'},
    {'osver': '24.04', 'pkgname': 'sssd-tools', 'pkgver': '2.9.4-1.1ubuntu6.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa-hbac-dev / libipa-hbac0 / libipa-hbac0t64 / libnss-sss / etc');
}
