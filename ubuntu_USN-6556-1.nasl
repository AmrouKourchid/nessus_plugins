#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6556-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186990);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-49342",
    "CVE-2023-49343",
    "CVE-2023-49344",
    "CVE-2023-49345",
    "CVE-2023-49346",
    "CVE-2023-49347"
  );
  script_xref(name:"USN", value:"6556-1");

  script_name(english:"Ubuntu 22.04 LTS / 23.04 / 23.10 : Budgie Extras vulnerabilities (USN-6556-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6556-1 advisory.

    It was discovered that Budgie Extras incorrectly handled certain temporary file paths. An attacker could
    possibly use this issue to inject false information or deny access to the application. (CVE-2023-49342,
    CVE-2023-49343, CVE-2023-49347)

    Matthias Gerstner discovered that Budgie Extras incorrectly handled certain temporary file paths. A local
    attacker could use this to inject arbitrary PNG data in this path and have it displayed on the victim's
    desktop or deny access to the application. (CVE-2023-49344)

    Matthias Gerstner discovered that Budgie Extras incorrectly handled certain temporary file paths. A local
    attacker could use this to inject false information or deny access to the application. (CVE-2023-49345,
    CVE-2023-49346)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6556-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-app-launcher-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-applications-menu-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-brightness-controller-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-clockworks-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-countdown-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-dropby-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-extras-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-extras-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-fuzzyclock-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-hotcorners-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-kangaroo-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-keyboard-autoswitch-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-previews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-previews-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-quickchar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-quicknote-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-recentlyused-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-rotation-lock-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-showtime-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-takeabreak-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-trash-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-visualspace-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-wallstreet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-weathershow-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-window-shuffler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-workspace-stopwatch-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:budgie-workspace-wallpaper-applet");
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
if (! ('22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'budgie-app-launcher-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-applications-menu-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-brightness-controller-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-clockworks-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-countdown-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-dropby-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-extras-common', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-extras-daemon', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-fuzzyclock-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-hotcorners-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-kangaroo-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-keyboard-autoswitch-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-network-manager-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-previews', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-previews-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-quickchar', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-quicknote-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-recentlyused-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-rotation-lock-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-showtime-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-takeabreak-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-trash-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-visualspace-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-wallstreet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-weathershow-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-window-shuffler', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-workspace-stopwatch-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'budgie-workspace-wallpaper-applet', 'pkgver': '1.4.0-1ubuntu3.1'},
    {'osver': '23.04', 'pkgname': 'budgie-app-launcher-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-applications-menu-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-brightness-controller-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-clockworks-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-countdown-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-dropby-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-extras-common', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-extras-daemon', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-fuzzyclock-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-hotcorners-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-kangaroo-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-keyboard-autoswitch-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-network-manager-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-previews', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-previews-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-quickchar', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-quicknote-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-recentlyused-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-rotation-lock-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-showtime-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-takeabreak-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-trash-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-visualspace-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-wallstreet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-weathershow-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-window-shuffler', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-workspace-stopwatch-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'budgie-workspace-wallpaper-applet', 'pkgver': '1.6.0-1ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'budgie-app-launcher-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-applications-menu-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-brightness-controller-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-clockworks-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-countdown-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-dropby-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-extras-common', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-extras-daemon', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-fuzzyclock-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-hotcorners-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-kangaroo-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-keyboard-autoswitch-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-network-manager-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-previews', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-quickchar', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-quicknote-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-recentlyused-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-rotation-lock-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-showtime-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-takeabreak-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-trash-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-visualspace-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-wallstreet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-weathershow-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-window-shuffler', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-workspace-stopwatch-applet', 'pkgver': '1.7.0-3.0ubuntu1'},
    {'osver': '23.10', 'pkgname': 'budgie-workspace-wallpaper-applet', 'pkgver': '1.7.0-3.0ubuntu1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'budgie-app-launcher-applet / budgie-applications-menu-applet / etc');
}
