#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3685-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110551);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-0898",
    "CVE-2017-0901",
    "CVE-2017-0902",
    "CVE-2017-0903",
    "CVE-2017-10784",
    "CVE-2017-14064",
    "CVE-2017-17742",
    "CVE-2018-1000074",
    "CVE-2018-8777"
  );
  script_xref(name:"USN", value:"3685-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Ruby vulnerabilities (USN-3685-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3685-1 advisory.

    Some of these CVE were already addressed in previous USN: 3439-1, 3553-1, 3528-1. Here we address for the
    remain releases.

    It was discovered that Ruby incorrectly handled certain inputs. An attacker could use this to cause a
    buffer overrun. (CVE-2017-0898)

    It was discovered that Ruby incorrectly handled certain files. An attacker could use this to overwrite any
    file on the filesystem. (CVE-2017-0901)

    It was discovered that Ruby was vulnerable to a DNS hijacking vulnerability. An attacker could use this to
    possibly force the RubyGems client to download and install gems from a server that the attacker controls.
    (CVE-2017-0902)

    It was discovered that Ruby incorrectly handled certain YAML files. An attacker could use this to possibly
    execute arbitrary code. (CVE-2017-0903)

    It was discovered that Ruby incorrectly handled certain files. An attacker could use this to expose
    sensitive information. (CVE-2017-14064)

    It was discovered that Ruby incorrectly handled certain inputs. An attacker could use this to execute
    arbitrary code. (CVE-2017-10784)

    It was discovered that Ruby incorrectly handled certain network requests. An attacker could possibly use
    this to inject a crafted key into a HTTP response. (CVE-2017-17742)

    It was discovered that Ruby incorrectly handled certain files. An attacker could possibly use this to
    execute arbitrary code. This update is only addressed to ruby2.0. (CVE-2018-1000074)

    It was discovered that Ruby incorrectly handled certain network requests. An attacker could possibly use
    this to cause a denial of service. (CVE-2018-8777)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3685-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10784");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-14064");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtcltk-ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ri1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.1-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.1-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.0-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.3-tcltk");
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
    {'osver': '14.04', 'pkgname': 'libruby1.9.1', 'pkgver': '1.9.3.484-2ubuntu1.12'},
    {'osver': '14.04', 'pkgname': 'libruby2.0', 'pkgver': '2.0.0.484-1ubuntu2.10'},
    {'osver': '14.04', 'pkgname': 'libtcltk-ruby1.9.1', 'pkgver': '1.9.3.484-2ubuntu1.12'},
    {'osver': '14.04', 'pkgname': 'ri1.9.1', 'pkgver': '1.9.3.484-2ubuntu1.12'},
    {'osver': '14.04', 'pkgname': 'ruby1.9.1', 'pkgver': '1.9.3.484-2ubuntu1.12'},
    {'osver': '14.04', 'pkgname': 'ruby1.9.1-dev', 'pkgver': '1.9.3.484-2ubuntu1.12'},
    {'osver': '14.04', 'pkgname': 'ruby1.9.1-examples', 'pkgver': '1.9.3.484-2ubuntu1.12'},
    {'osver': '14.04', 'pkgname': 'ruby1.9.1-full', 'pkgver': '1.9.3.484-2ubuntu1.12'},
    {'osver': '14.04', 'pkgname': 'ruby1.9.3', 'pkgver': '1.9.3.484-2ubuntu1.12'},
    {'osver': '14.04', 'pkgname': 'ruby2.0', 'pkgver': '2.0.0.484-1ubuntu2.10'},
    {'osver': '14.04', 'pkgname': 'ruby2.0-dev', 'pkgver': '2.0.0.484-1ubuntu2.10'},
    {'osver': '14.04', 'pkgname': 'ruby2.0-tcltk', 'pkgver': '2.0.0.484-1ubuntu2.10'},
    {'osver': '16.04', 'pkgname': 'libruby2.3', 'pkgver': '2.3.1-2~16.04.10'},
    {'osver': '16.04', 'pkgname': 'ruby2.3', 'pkgver': '2.3.1-2~16.04.10'},
    {'osver': '16.04', 'pkgname': 'ruby2.3-dev', 'pkgver': '2.3.1-2~16.04.10'},
    {'osver': '16.04', 'pkgname': 'ruby2.3-tcltk', 'pkgver': '2.3.1-2~16.04.10'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libruby1.9.1 / libruby2.0 / libruby2.3 / libtcltk-ruby1.9.1 / etc');
}
