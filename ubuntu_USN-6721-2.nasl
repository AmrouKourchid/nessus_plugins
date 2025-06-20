#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6721-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193128);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");
  script_xref(name:"USN", value:"6721-2");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 : X.Org X Server regression (USN-6721-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are
affected by a vulnerability as referenced in the USN-6721-2 advisory.

    USN-6721-1 fixed vulnerabilities in X.Org X Server. That fix was incomplete resulting in a regression.
    This update fixes the problem.

    We apologize for the inconvenience.



Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6721-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-xmir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xwayland");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '14.04', 'pkgname': 'xdmx', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xnest', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'xvfb', 'pkgver': '2:1.15.1-0ubuntu2.11+esm12', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xdmx', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xmir', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xnest', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xvfb', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'xwayland', 'pkgver': '2:1.18.4-0ubuntu0.12+esm13', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xdmx', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xmir', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xnest', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-xmir', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xvfb', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xwayland', 'pkgver': '2:1.19.6-1ubuntu4.15+esm8', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'xdmx', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xdmx-tools', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xnest', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xserver-common', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xvfb', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xwayland', 'pkgver': '2:1.20.13-1ubuntu1~20.04.17', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xnest', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xorg-server-source', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xserver-common', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xserver-xephyr', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xvfb', 'pkgver': '2:21.1.4-2ubuntu1.7~22.04.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xwayland', 'pkgver': '2:22.1.1-1ubuntu0.13', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xnest', 'pkgver': '2:21.1.7-3ubuntu2.9', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xorg-server-source', 'pkgver': '2:21.1.7-3ubuntu2.9', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xserver-common', 'pkgver': '2:21.1.7-3ubuntu2.9', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xserver-xephyr', 'pkgver': '2:21.1.7-3ubuntu2.9', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xserver-xorg-core', 'pkgver': '2:21.1.7-3ubuntu2.9', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xserver-xorg-dev', 'pkgver': '2:21.1.7-3ubuntu2.9', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xserver-xorg-legacy', 'pkgver': '2:21.1.7-3ubuntu2.9', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xvfb', 'pkgver': '2:21.1.7-3ubuntu2.9', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xwayland', 'pkgver': '2:23.2.0-1ubuntu0.6', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xmir / xnest / xorg-server-source / etc');
}
