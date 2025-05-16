#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4994-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150940);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-13950",
    "CVE-2020-35452",
    "CVE-2021-26690",
    "CVE-2021-26691",
    "CVE-2021-30641"
  );
  script_xref(name:"USN", value:"4994-1");
  script_xref(name:"IAVA", value:"2021-A-0259-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Apache HTTP Server vulnerabilities (USN-4994-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4994-1 advisory.

    Marc Stern discovered that the Apache mod_proxy_http module incorrectly handled certain requests. A remote
    attacker could possibly use this issue to cause Apache to crash, resulting in a denial of service. This
    issue only affected Ubuntu 20.04 LTS, Ubuntu 20.10, and Ubuntu 21.04. (CVE-2020-13950)

    Antonio Morales discovered that the Apache mod_auth_digest module incorrectly handled certain Digest
    nonces. A remote attacker could possibly use this issue to cause Apache to crash, resulting in a denial of
    service. (CVE-2020-35452)

    Antonio Morales discovered that the Apache mod_session module incorrectly handled certain Cookie headers.
    A remote attacker could possibly use this issue to cause Apache to crash, resulting in a denial of
    service. (CVE-2021-26690)

    Christophe Jaillet discovered that the Apache mod_session module incorrectly handled certain SessionHeader
    values. A remote attacker could use this issue to cause Apache to crash, resulting in a denial of service,
    or possibly execute arbitrary code. (CVE-2021-26691)

    Christoph Anton Mitterer discovered that the new MergeSlashes configuration option resulted in unexpected
    behaviour in certain situations. (CVE-2021-30641)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4994-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26691");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-proxy-uwsgi");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'osver': '18.04', 'pkgname': 'apache2', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '18.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.29-1ubuntu4.16'},
    {'osver': '20.04', 'pkgname': 'apache2', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.41-4ubuntu3.3'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.41-4ubuntu3.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / etc');
}
