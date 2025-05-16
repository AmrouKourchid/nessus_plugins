#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6526-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186441);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id(
    "CVE-2023-37329",
    "CVE-2023-40474",
    "CVE-2023-40475",
    "CVE-2023-40476",
    "CVE-2023-44429",
    "CVE-2023-44446"
  );
  script_xref(name:"USN", value:"6526-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : GStreamer Bad Plugins vulnerabilities (USN-6526-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6526-1 advisory.

    It was discovered that GStreamer Bad Plugins incorrectly handled certain media files. A remote attacker
    could use this issue to cause GStreamer Bad Plugins to crash, resulting in a denial of service, or
    possibly execute arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6526-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44446");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gst-plugins-bad-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-plugins-bad-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-wpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-opencv1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-bad1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-bad1.0-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gir1.2-gst-plugins-bad-1.0', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-opencv', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-plugins-bad', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libgstreamer-opencv1.0-0', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libgstreamer-plugins-bad1.0-0', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libgstreamer-plugins-bad1.0-dev', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-gst-plugins-bad-1.0', 'pkgver': '1.20.3-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-opencv', 'pkgver': '1.20.3-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-plugins-bad', 'pkgver': '1.20.3-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-plugins-bad-apps', 'pkgver': '1.20.3-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'gstreamer1.0-wpe', 'pkgver': '1.20.3-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libgstreamer-opencv1.0-0', 'pkgver': '1.20.3-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libgstreamer-plugins-bad1.0-0', 'pkgver': '1.20.3-0ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libgstreamer-plugins-bad1.0-dev', 'pkgver': '1.20.3-0ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'gir1.2-gst-plugins-bad-1.0', 'pkgver': '1.22.1-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'gstreamer1.0-opencv', 'pkgver': '1.22.1-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'gstreamer1.0-plugins-bad', 'pkgver': '1.22.1-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'gstreamer1.0-plugins-bad-apps', 'pkgver': '1.22.1-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libgstreamer-opencv1.0-0', 'pkgver': '1.22.1-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libgstreamer-plugins-bad1.0-0', 'pkgver': '1.22.1-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'libgstreamer-plugins-bad1.0-dev', 'pkgver': '1.22.1-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'gir1.2-gst-plugins-bad-1.0', 'pkgver': '1.22.4-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'gstreamer1.0-opencv', 'pkgver': '1.22.4-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'gstreamer1.0-plugins-bad', 'pkgver': '1.22.4-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'gstreamer1.0-plugins-bad-apps', 'pkgver': '1.22.4-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libgstreamer-opencv1.0-0', 'pkgver': '1.22.4-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libgstreamer-plugins-bad1.0-0', 'pkgver': '1.22.4-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libgstreamer-plugins-bad1.0-dev', 'pkgver': '1.22.4-1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-gst-plugins-bad-1.0 / gstreamer1.0-opencv / etc');
}
