#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3286-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100217);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2017-8422");
  script_xref(name:"USN", value:"3286-1");

  script_name(english:"Ubuntu 14.04 LTS : KDE-Libs vulnerability (USN-3286-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-3286-1 advisory.

    Sebastian Krahmer discovered that the KDE-Libs Kauth component incorrectly checked services invoking
    D-Bus. A local attacker could use this issue to gain root privileges.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3286-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8422");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdoctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkcmutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkde3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdeclarative5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdecore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdesu5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdeui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdewebkit5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdnssd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkemoticons4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkfile4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkhtml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkidletime4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkimproxy4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkio5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkjsapi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkjsembed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkmediaplayer4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libknewstuff2-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libknewstuff3-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libknotifyconfig4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkntlm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkparts4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkprintutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpty4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrosscore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrossui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libktexteditor4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkunitconversion4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnepomuk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnepomukquery4a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnepomukutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libplasma3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsolid4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libthreadweaver4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2024 Canonical, Inc. / NASL script (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'kdelibs-bin', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'kdelibs5-data', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'kdelibs5-dev', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'kdelibs5-plugins', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'kdoctools', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkcmutils4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkde3support4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkdeclarative5', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkdecore5', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkdesu5', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkdeui5', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkdewebkit5', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkdnssd4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkemoticons4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkfile4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkhtml5', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkidletime4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkimproxy4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkio5', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkjsapi4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkjsembed4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkmediaplayer4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libknewstuff2-4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libknewstuff3-4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libknotifyconfig4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkntlm4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkparts4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkprintutils4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkpty4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkrosscore4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkrossui4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libktexteditor4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkunitconversion4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libkutils4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libnepomuk4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libnepomukquery4a', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libnepomukutils4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libplasma3', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libsolid4', 'pkgver': '4:4.13.3-0ubuntu0.5'},
    {'osver': '14.04', 'pkgname': 'libthreadweaver4', 'pkgver': '4:4.13.3-0ubuntu0.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kdelibs-bin / kdelibs5-data / kdelibs5-dev / kdelibs5-plugins / etc');
}
