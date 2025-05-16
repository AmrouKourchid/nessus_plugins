#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6899-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202475);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2024-6655");
  script_xref(name:"USN", value:"6899-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS : GTK vulnerability (USN-6899-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-6899-1 advisory.

    It was discovered that GTK would attempt to load modules from the current directory, contrary to
    expectations. If users started GTK applications from shared directories, a local attacker could use this
    issue to execute arbitrary code, and possibly escalate privileges.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6899-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gtk-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gtk-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gtk-3-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gtk2-engines-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gtk2.0-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgail-3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgail-3-0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgail-3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgail-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgail-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgail18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgail18t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk-3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk-3-0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk-3-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk-3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk-3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgtk2.0-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gir1.2-gtk-2.0', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-gtk-3.0', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'gtk-3-examples', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'gtk-update-icon-cache', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'gtk2-engines-pixbuf', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'gtk2.0-examples', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgail-3-0', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libgail-3-dev', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libgail-common', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgail-dev', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgail18', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgtk-3-0', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libgtk-3-bin', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libgtk-3-common', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libgtk-3-dev', 'pkgver': '3.24.20-0ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'libgtk2.0-0', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgtk2.0-bin', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgtk2.0-common', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '20.04', 'pkgname': 'libgtk2.0-dev', 'pkgver': '2.24.32-4ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-gtk-2.0', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-gtk-3.0', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'gtk-3-examples', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'gtk-update-icon-cache', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'gtk2-engines-pixbuf', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'gtk2.0-examples', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libgail-3-0', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libgail-3-dev', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libgail-common', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libgail-dev', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libgail18', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libgtk-3-0', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libgtk-3-bin', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libgtk-3-common', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libgtk-3-dev', 'pkgver': '3.24.33-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libgtk2.0-0', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libgtk2.0-bin', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libgtk2.0-common', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libgtk2.0-dev', 'pkgver': '2.24.33-2ubuntu2.1'},
    {'osver': '24.04', 'pkgname': 'gir1.2-gtk-2.0', 'pkgver': '2.24.33-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'gir1.2-gtk-3.0', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'gtk-3-examples', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'gtk-update-icon-cache', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'gtk2-engines-pixbuf', 'pkgver': '2.24.33-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgail-3-0t64', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgail-3-dev', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgail-common', 'pkgver': '2.24.33-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgail-dev', 'pkgver': '2.24.33-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgail18t64', 'pkgver': '2.24.33-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgtk-3-0t64', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgtk-3-bin', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgtk-3-common', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgtk-3-dev', 'pkgver': '3.24.41-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgtk2.0-0t64', 'pkgver': '2.24.33-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgtk2.0-bin', 'pkgver': '2.24.33-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgtk2.0-common', 'pkgver': '2.24.33-4ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libgtk2.0-dev', 'pkgver': '2.24.33-4ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-gtk-2.0 / gir1.2-gtk-3.0 / gtk-3-examples / etc');
}
