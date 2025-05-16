#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4213-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131723);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-12523",
    "CVE-2019-12526",
    "CVE-2019-12854",
    "CVE-2019-18676",
    "CVE-2019-18677",
    "CVE-2019-18678",
    "CVE-2019-18679"
  );
  script_xref(name:"USN", value:"4213-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Squid vulnerabilities (USN-4213-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4213-1 advisory.

    Jeriko One and Kristoffer Danielsson discovered that Squid incorrectly handled certain URN requests. A
    remote attacker could possibly use this issue to bypass access checks and access restricted servers. This
    issue was only addressed in Ubuntu 19.04 and Ubuntu 19.10. (CVE-2019-12523)

    Jeriko One discovered that Squid incorrectly handed URN responses. A remote attacker could use this issue
    to cause Squid to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2019-12526)

    Alex Rousskov discovered that Squid incorrectly handled certain strings. A remote attacker could possibly
    use this issue to cause Squid to crash, resulting in a denial of service. This issue only affected Ubuntu
    19.04. (CVE-2019-12854)

    Jeriko One and Kristoffer Danielsson discovered that Squid incorrectly handled certain input. A remote
    attacker could use this issue to cause Squid to crash, resulting in a denial of service, or possibly
    execute arbitrary code. This issue was only addressed in Ubuntu 19.04 and Ubuntu 19.10. (CVE-2019-18676)

    Kristoffer Danielsson discovered that Squid incorrectly handled certain messages. This issue could result
    in traffic being redirected to origins it should not be delivered to. (CVE-2019-18677)

    Rgis Leroy discovered that Squid incorrectly handled certain HTTP request headers. A remote attacker
    could use this to smuggle HTTP requests and corrupt caches with arbitrary content. (CVE-2019-18678)

    David Fifield discovered that Squid incorrectly handled HTTP Digest Authentication. A remote attacker
    could possibly use this issue to obtain pointer contents and bypass ASLR protections. (CVE-2019-18679)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4213-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squidclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'squid', 'pkgver': '3.5.12-1ubuntu7.9'},
    {'osver': '16.04', 'pkgname': 'squid-cgi', 'pkgver': '3.5.12-1ubuntu7.9'},
    {'osver': '16.04', 'pkgname': 'squid-common', 'pkgver': '3.5.12-1ubuntu7.9'},
    {'osver': '16.04', 'pkgname': 'squid-purge', 'pkgver': '3.5.12-1ubuntu7.9'},
    {'osver': '16.04', 'pkgname': 'squid3', 'pkgver': '3.5.12-1ubuntu7.9'},
    {'osver': '16.04', 'pkgname': 'squidclient', 'pkgver': '3.5.12-1ubuntu7.9'},
    {'osver': '18.04', 'pkgname': 'squid', 'pkgver': '3.5.27-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'squid-cgi', 'pkgver': '3.5.27-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'squid-common', 'pkgver': '3.5.27-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'squid-purge', 'pkgver': '3.5.27-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'squid3', 'pkgver': '3.5.27-1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'squidclient', 'pkgver': '3.5.27-1ubuntu1.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'squid / squid-cgi / squid-common / squid-purge / squid3 / etc');
}
