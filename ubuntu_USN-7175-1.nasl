#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7175-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213188);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_cve_id(
    "CVE-2024-47538",
    "CVE-2024-47541",
    "CVE-2024-47542",
    "CVE-2024-47600",
    "CVE-2024-47607",
    "CVE-2024-47615",
    "CVE-2024-47835"
  );
  script_xref(name:"USN", value:"7175-1");
  script_xref(name:"IAVA", value:"2024-A-0832-S");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : GStreamer Base Plugins vulnerabilities (USN-7175-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7175-1 advisory.

    Antonio Morales discovered that GStreamer Base Plugins incorrectly handled certain malformed media files.
    An attacker could use these issues to cause GStreamer Base Plugins to crash, resulting in a denial of
    service, or possibly execute arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7175-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47615");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gst-plugins-base-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-plugins-base-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-gl1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-base1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-base1.0-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gir1.2-gst-plugins-base-1.0', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-alsa', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-gl', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-plugins-base', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-plugins-base-apps', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-x', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libgstreamer-gl1.0-0', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libgstreamer-plugins-base1.0-0', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libgstreamer-plugins-base1.0-dev', 'pkgver': '1.16.3-0ubuntu1.4'},
    {'osver': '22.04', 'pkgname': 'gir1.2-gst-plugins-base-1.0', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-alsa', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-gl', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-plugins-base', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-plugins-base-apps', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-x', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'libgstreamer-gl1.0-0', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'libgstreamer-plugins-base1.0-0', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'libgstreamer-plugins-base1.0-dev', 'pkgver': '1.20.1-1ubuntu0.4'},
    {'osver': '24.04', 'pkgname': 'gir1.2-gst-plugins-base-1.0', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'gstreamer1.0-alsa', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'gstreamer1.0-gl', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'gstreamer1.0-plugins-base', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'gstreamer1.0-plugins-base-apps', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'gstreamer1.0-x', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libgstreamer-gl1.0-0', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libgstreamer-plugins-base1.0-0', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.04', 'pkgname': 'libgstreamer-plugins-base1.0-dev', 'pkgver': '1.24.2-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'gir1.2-gst-plugins-base-1.0', 'pkgver': '1.24.8-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'gstreamer1.0-alsa', 'pkgver': '1.24.8-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'gstreamer1.0-gl', 'pkgver': '1.24.8-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'gstreamer1.0-plugins-base', 'pkgver': '1.24.8-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'gstreamer1.0-plugins-base-apps', 'pkgver': '1.24.8-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'gstreamer1.0-x', 'pkgver': '1.24.8-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libgstreamer-gl1.0-0', 'pkgver': '1.24.8-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libgstreamer-plugins-base1.0-0', 'pkgver': '1.24.8-1ubuntu0.1'},
    {'osver': '24.10', 'pkgname': 'libgstreamer-plugins-base1.0-dev', 'pkgver': '1.24.8-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-gst-plugins-base-1.0 / gstreamer1.0-alsa / gstreamer1.0-gl / etc');
}
