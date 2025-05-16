#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6894-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202245);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id(
    "CVE-2021-3899",
    "CVE-2022-1242",
    "CVE-2022-28652",
    "CVE-2022-28654",
    "CVE-2022-28655",
    "CVE-2022-28656",
    "CVE-2022-28657",
    "CVE-2022-28658"
  );
  script_xref(name:"USN", value:"6894-1");

  script_name(english:"Ubuntu 16.04 LTS : Apport vulnerabilities (USN-6894-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-6894-1 advisory.

    Muqing Liu and neoni discovered that Apport incorrectly handled detecting if an executable was replaced
    after a crash. A local attacker could possibly use this issue to execute arbitrary code as the root user.
    (CVE-2021-3899)

    Gerrit Venema discovered that Apport incorrectly handled connections to Apport sockets inside containers.
    A local attacker could possibly use this issue to connect to arbitrary sockets as the root user.
    (CVE-2022-1242)

    Gerrit Venema discovered that Apport incorrectly handled user settings files. A local attacker could
    possibly use this issue to cause Apport to consume resources, leading to a denial of service.
    (CVE-2022-28652)

    Gerrit Venema discovered that Apport did not limit the amount of logging from D-Bus connections. A local
    attacker could possibly use this issue to fill up the Apport log file, leading to a denial of service.
    (CVE-2022-28654)

    Gerrit Venema discovered that Apport did not filter D-Bus connection strings. A local attacker could
    possibly use this issue to cause Apport to make arbitrary network connections. (CVE-2022-28655)

    Gerrit Venema discovered that Apport did not limit the amount of memory being consumed during D-Bus
    connections. A local attacker could possibly use this issue to cause Apport to consume memory, leading to
    a denial of service. (CVE-2022-28656)

    Gerrit Venema discovered that Apport did not disable the python crash handler before chrooting into a
    container. A local attacker could possibly use this issue to execute arbitrary code. (CVE-2022-28657)

    Gerrit Venema discovered that Apport incorrectly handled filename argument whitespace. A local attacker
    could possibly use this issue to spoof arguments to the Apport daemon. (CVE-2022-28658)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6894-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-noui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-retrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-valgrind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dh-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-problem-report");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-problem-report");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'apport', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'apport-gtk', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'apport-kde', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'apport-noui', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'apport-retrace', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'dh-apport', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python-apport', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python-problem-report', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3-apport', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.1-0ubuntu2.30+esm4', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apport / apport-gtk / apport-kde / apport-noui / apport-retrace / etc');
}
