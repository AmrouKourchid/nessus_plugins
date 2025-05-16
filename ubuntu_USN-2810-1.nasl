#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2810-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86872);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2002-2443",
    "CVE-2014-5355",
    "CVE-2015-2694",
    "CVE-2015-2695",
    "CVE-2015-2696",
    "CVE-2015-2697",
    "CVE-2015-2698"
  );
  script_xref(name:"USN", value:"2810-1");

  script_name(english:"Ubuntu 14.04 LTS : Kerberos vulnerabilities (USN-2810-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2810-1 advisory.

    It was discovered that the Kerberos kpasswd service incorrectly handled certain UDP packets. A remote
    attacker could possibly use this issue to cause resource consumption, resulting in a denial of service.
    This issue only affected Ubuntu 12.04 LTS. (CVE-2002-2443)

    It was discovered that Kerberos incorrectly handled null bytes in certain data fields. A remote attacker
    could possibly use this issue to cause a denial of service. This issue only affected Ubuntu 12.04 LTS and
    Ubuntu 14.04 LTS. (CVE-2014-5355)

    It was discovered that the Kerberos kdcpreauth modules incorrectly tracked certain client requests. A
    remote attacker could possibly use this issue to bypass intended preauthentication requirements. This
    issue only affected Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-2694)

    It was discovered that Kerberos incorrectly handled certain SPNEGO packets. A remote attacker could
    possibly use this issue to cause a denial of service. (CVE-2015-2695)

    It was discovered that Kerberos incorrectly handled certain IAKERB packets. A remote attacker could
    possibly use this issue to cause a denial of service. (CVE-2015-2696, CVE-2015-2698)

    It was discovered that Kerberos incorrectly handled certain TGS requests. A remote attacker could possibly
    use this issue to cause a denial of service. (CVE-2015-2697)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2810-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2698");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-5355");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-gss-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
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
    {'osver': '14.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'krb5-locales', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'krb5-otp', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'krb5-user', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkadm5clnt-mit9', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkadm5srv-mit8', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkadm5srv-mit9', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkdb5-7', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkrad0', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.12+dfsg-2ubuntu5.2'},
    {'osver': '14.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.12+dfsg-2ubuntu5.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-admin-server / krb5-gss-samples / krb5-kdc / krb5-kdc-ldap / etc');
}
