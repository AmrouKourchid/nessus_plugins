#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3244-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(99023);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-9811",
    "CVE-2017-5837",
    "CVE-2017-5839",
    "CVE-2017-5842",
    "CVE-2017-5844"
  );
  script_xref(name:"USN", value:"3244-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : GStreamer Base Plugins vulnerabilities (USN-3244-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3244-1 advisory.

    Hanno Bck discovered that GStreamer Base Plugins did not correctly handle certain malformed media files.
    If a user were tricked into opening a crafted media file with a GStreamer application, an attacker could
    cause a denial of service via application crash.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3244-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5839");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-base-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-plugins-base-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-base0.10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-base0.10-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-base1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-base1.0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gst-plugins-base-0.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gst-plugins-base-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-gnomevfs");
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
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'gir1.2-gst-plugins-base-0.10', 'pkgver': '0.10.36-1.1ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gir1.2-gst-plugins-base-1.0', 'pkgver': '1.2.4-1~ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer0.10-alsa', 'pkgver': '0.10.36-1.1ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer0.10-gnomevfs', 'pkgver': '0.10.36-1.1ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer0.10-plugins-base', 'pkgver': '0.10.36-1.1ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer0.10-plugins-base-apps', 'pkgver': '0.10.36-1.1ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer0.10-x', 'pkgver': '0.10.36-1.1ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer1.0-alsa', 'pkgver': '1.2.4-1~ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer1.0-plugins-base', 'pkgver': '1.2.4-1~ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer1.0-plugins-base-apps', 'pkgver': '1.2.4-1~ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'gstreamer1.0-x', 'pkgver': '1.2.4-1~ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'libgstreamer-plugins-base0.10-0', 'pkgver': '0.10.36-1.1ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'libgstreamer-plugins-base0.10-dev', 'pkgver': '0.10.36-1.1ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'libgstreamer-plugins-base1.0-0', 'pkgver': '1.2.4-1~ubuntu2.1'},
    {'osver': '14.04', 'pkgname': 'libgstreamer-plugins-base1.0-dev', 'pkgver': '1.2.4-1~ubuntu2.1'},
    {'osver': '16.04', 'pkgname': 'gir1.2-gst-plugins-base-1.0', 'pkgver': '1.8.3-1ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'gstreamer1.0-alsa', 'pkgver': '1.8.3-1ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'gstreamer1.0-plugins-base', 'pkgver': '1.8.3-1ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'gstreamer1.0-plugins-base-apps', 'pkgver': '1.8.3-1ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'gstreamer1.0-x', 'pkgver': '1.8.3-1ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libgstreamer-plugins-base1.0-0', 'pkgver': '1.8.3-1ubuntu0.2'},
    {'osver': '16.04', 'pkgname': 'libgstreamer-plugins-base1.0-dev', 'pkgver': '1.8.3-1ubuntu0.2'}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-gst-plugins-base-0.10 / gir1.2-gst-plugins-base-1.0 / etc');
}
