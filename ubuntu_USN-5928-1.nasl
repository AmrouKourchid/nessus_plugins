#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5928-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172227);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2022-3821", "CVE-2022-4415", "CVE-2022-45873");
  script_xref(name:"USN", value:"5928-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS : systemd vulnerabilities (USN-5928-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5928-1 advisory.

    It was discovered that systemd did not properly validate the time and accuracy values provided to the
    format_timespan() function. An attacker could possibly use this issue to cause a buffer overrun, leading
    to a denial of service attack. This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM, Ubuntu 18.04
    LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-3821)

    It was discovered that systemd did not properly manage the fs.suid_dumpable kernel configurations. A local
    attacker could possibly use this issue to expose sensitive information. This issue only affected Ubuntu
    20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 22.10. (CVE-2022-4415)

    It was discovered that systemd did not properly manage a crash with long backtrace data. A local attacker
    could possibly use this issue to cause a deadlock, leading to a denial of service attack. This issue only
    affected Ubuntu 22.10. (CVE-2022-45873)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5928-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4415");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-gudev-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgudev-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgudev-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-daemon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-daemon0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-id128-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-id128-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-journal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-journal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-login-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd-login0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-oomd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-repart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-standalone-sysusers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-standalone-tmpfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:systemd-timesyncd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libnss-myhostname', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libnss-mymachines', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libnss-resolve', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpam-systemd', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libsystemd-dev', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libsystemd0', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libudev-dev', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libudev1', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'systemd', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'systemd-container', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'systemd-coredump', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'systemd-sysv', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'udev', 'pkgver': '229-4ubuntu21.31+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libnss-myhostname', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libnss-mymachines', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libnss-resolve', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libnss-systemd', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpam-systemd', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libsystemd-dev', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libsystemd0', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libudev-dev', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libudev1', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'systemd', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'systemd-container', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'systemd-coredump', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'systemd-sysv', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'systemd-tests', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'udev', 'pkgver': '237-3ubuntu10.57', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libnss-myhostname', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libnss-mymachines', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libnss-resolve', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libnss-systemd', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpam-systemd', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libsystemd-dev', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libsystemd0', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libudev-dev', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libudev1', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'systemd', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'systemd-container', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'systemd-coredump', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'systemd-sysv', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'systemd-tests', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'systemd-timesyncd', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'udev', 'pkgver': '245.4-4ubuntu3.20', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libnss-myhostname', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libnss-mymachines', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libnss-resolve', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libnss-systemd', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpam-systemd', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libsystemd-dev', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libsystemd0', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libudev-dev', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libudev1', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-container', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-coredump', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-journal-remote', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-oomd', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-repart', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-standalone-sysusers', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-standalone-tmpfiles', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-sysv', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-tests', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'systemd-timesyncd', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'udev', 'pkgver': '249.11-0ubuntu3.7', 'ubuntu_pro': FALSE}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-myhostname / libnss-mymachines / libnss-resolve / etc');
}
