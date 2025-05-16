#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4131-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128756);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-13962",
    "CVE-2019-14437",
    "CVE-2019-14438",
    "CVE-2019-14498",
    "CVE-2019-14533",
    "CVE-2019-14534",
    "CVE-2019-14535",
    "CVE-2019-14776",
    "CVE-2019-14777",
    "CVE-2019-14778",
    "CVE-2019-14970"
  );
  script_xref(name:"USN", value:"4131-1");

  script_name(english:"Ubuntu 18.04 LTS : VLC vulnerabilities (USN-4131-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4131-1 advisory.

    It was discovered that VLC incorrectly handled certain media files. If a user were tricked into opening a
    specially-crafted file, a remote attacker could use this issue to cause VLC to crash, resulting in a
    denial of service, or possibly execute arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4131-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13962");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-access-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-skins2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-video-output");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-video-splitter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-visualization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlc-plugin-zvbi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlccore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvlccore9");
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
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libvlc-bin', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'libvlc-dev', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'libvlc5', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'libvlccore-dev', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'libvlccore9', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-bin', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-data', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-l10n', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-access-extra', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-base', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-fluidsynth', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-jack', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-notify', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-qt', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-samba', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-skins2', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-svg', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-video-output', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-video-splitter', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-visualization', 'pkgver': '3.0.8-0ubuntu18.04.1'},
    {'osver': '18.04', 'pkgname': 'vlc-plugin-zvbi', 'pkgver': '3.0.8-0ubuntu18.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvlc-bin / libvlc-dev / libvlc5 / libvlccore-dev / libvlccore9 / etc');
}
