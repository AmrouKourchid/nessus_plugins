#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4099-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128024);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516");
  script_xref(name:"USN", value:"4099-1");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : nginx vulnerabilities (USN-4099-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4099-1 advisory.

    Jonathan Looney discovered that nginx incorrectly handled the HTTP/2 implementation. A remote attacker
    could possibly use this issue to consume resources, leading to a denial of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4099-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-light");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-auth-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-cache-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-dav-ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-echo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-fancyindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-headers-more-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-ndk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-subs-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-uploadprogress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-upstream-fair");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-nchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-rtmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx");
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
    {'osver': '16.04', 'pkgname': 'nginx', 'pkgver': '1.10.3-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'nginx-common', 'pkgver': '1.10.3-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'nginx-core', 'pkgver': '1.10.3-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'nginx-extras', 'pkgver': '1.10.3-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'nginx-full', 'pkgver': '1.10.3-0ubuntu0.16.04.4'},
    {'osver': '16.04', 'pkgname': 'nginx-light', 'pkgver': '1.10.3-0ubuntu0.16.04.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-auth-pam', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-cache-purge', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-dav-ext', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-echo', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-fancyindex', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-geoip', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-headers-more-filter', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-image-filter', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-lua', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-ndk', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-perl', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-subs-filter', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-uploadprogress', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-upstream-fair', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-xslt-filter', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-mail', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-nchan', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-rtmp', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-stream', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'nginx', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'nginx-common', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'nginx-core', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'nginx-extras', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'nginx-full', 'pkgver': '1.14.0-0ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'nginx-light', 'pkgver': '1.14.0-0ubuntu1.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnginx-mod-http-auth-pam / libnginx-mod-http-cache-purge / etc');
}
