##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4609-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142026);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2018-1000528", "CVE-2019-11187", "CVE-2019-14466");
  script_xref(name:"USN", value:"4609-1");

  script_name(english:"Ubuntu 16.04 LTS : GOsa vulnerabilities (USN-4609-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4609-1 advisory.

    Fabian Henneke discovered that GOsa incorrectly handled client cookies. An authenticated user could
    exploit this with a crafted cookie to perform file deletions in the context of the user account that runs
    the web server. (CVE-2019-14466)

    It was discovered that GOsa incorrectly handled user access control. A remote attacker could use this
    issue to log into any account with a username containing the word success. (CVE-2019-11187)

    Fabian Henneke discovered that GOsa was vulnerable to cross-site scripting attacks via the change password
    form. A remote attacker could use this flaw to run arbitrary web scripts. (CVE-2018-1000528)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4609-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-help-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-connectivity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-dhcp-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-dns-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-fai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-fai-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-gofax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-gofon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-goto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-kolab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-kolab-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-ldapmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-mit-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-mit-krb5-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-nagios-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-netatalk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-opengroupware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-openxchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-openxchange-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-opsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-phpgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-phpgw-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-phpscheduleit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-phpscheduleit-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-pptp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-pptp-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-pureftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-pureftpd-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-rolemanagement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-scalix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-ssh-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-sudo-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-systems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-uw-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-plugin-webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gosa-schema");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'gosa', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-desktop', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-dev', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-help-de', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-help-en', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-help-fr', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-help-nl', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-connectivity', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-dhcp', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-dhcp-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-dns', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-dns-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-fai', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-fai-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-gofax', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-gofon', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-goto', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-kolab', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-kolab-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-ldapmanager', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-mail', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-mit-krb5', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-mit-krb5-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-nagios', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-nagios-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-netatalk', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-opengroupware', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-openxchange', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-openxchange-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-opsi', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-phpgw', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-phpgw-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-phpscheduleit', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-phpscheduleit-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-pptp', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-pptp-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-pureftpd', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-pureftpd-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-rolemanagement', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-rsyslog', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-samba', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-scalix', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-squid', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-ssh', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-ssh-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-sudo', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-sudo-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-systems', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-uw-imap', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-plugin-webdav', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'},
    {'osver': '16.04', 'pkgname': 'gosa-schema', 'pkgver': '2.7.4+reloaded2-9ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gosa / gosa-desktop / gosa-dev / gosa-help-de / gosa-help-en / etc');
}
