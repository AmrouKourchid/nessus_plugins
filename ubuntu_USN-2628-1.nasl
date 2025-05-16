#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2628-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84045);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2015-4171");
  script_xref(name:"USN", value:"2628-1");

  script_name(english:"Ubuntu 14.04 LTS : strongSwan vulnerability (USN-2628-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-2628-1 advisory.

    Alexander E. Patrakov discovered that strongSwan incorrectly handled certain IKEv2 setups. A malicious
    server could possibly use this issue to obtain user credentials.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2628-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4171");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-ike");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-ikev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-ikev2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-af-alg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-attr-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-certexpire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-coupling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-dnscert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-dnskey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-duplicheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-aka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-aka-3gpp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-dynamic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-gtc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-mschapv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-peap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-sim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-sim-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-sim-pcsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-simaka-pseudonym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-simaka-reauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-simaka-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-tnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-eap-ttls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-error-notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-farp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-fips-prf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-gcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-ipseckey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-led");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-load-tester");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-lookip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-ntru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-pgp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-pubkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-radattr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-soup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-sshkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-systime-fix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-unity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-whitelist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-xauth-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-xauth-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-xauth-noauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-plugin-xauth-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-pt-tls-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-starter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-ifmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-pdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstrongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan");
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
    {'osver': '14.04', 'pkgname': 'libstrongswan', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-ike', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-ikev1', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-ikev2', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-nm', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-af-alg', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-agent', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-attr-sql', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-certexpire', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-coupling', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-curl', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-dhcp', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-dnscert', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-dnskey', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-duplicheck', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-aka', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-aka-3gpp2', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-dynamic', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-gtc', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-md5', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-mschapv2', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-peap', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-radius', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-sim', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-sim-file', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-sim-pcsc', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-simaka-pseudonym', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-simaka-reauth', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-simaka-sql', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-tls', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-tnc', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-eap-ttls', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-error-notify', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-farp', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-fips-prf', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-gcrypt', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-gmp', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-ipseckey', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-kernel-libipsec', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-ldap', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-led', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-load-tester', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-lookip', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-mysql', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-ntru', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-openssl', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-pgp', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-pkcs11', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-pubkey', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-radattr', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-soup', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-sql', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-sqlite', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-sshkey', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-systime-fix', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-unbound', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-unity', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-whitelist', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-xauth-eap', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-xauth-generic', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-xauth-noauth', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-plugin-xauth-pam', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-pt-tls-client', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-starter', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-tnc-base', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-tnc-client', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-tnc-ifmap', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-tnc-pdp', 'pkgver': '5.1.2-0ubuntu2.3'},
    {'osver': '14.04', 'pkgname': 'strongswan-tnc-server', 'pkgver': '5.1.2-0ubuntu2.3'}
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
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libstrongswan / strongswan / strongswan-ike / strongswan-ikev1 / etc');
}
