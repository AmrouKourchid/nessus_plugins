#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7320-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225810);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-5520", "CVE-2024-0321", "CVE-2024-0322");
  script_xref(name:"USN", value:"7320-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS : GPAC vulnerabilities (USN-7320-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS host has packages installed that
are affected by multiple vulnerabilities as referenced in the USN-7320-1 advisory.

    It was discovered that the GPAC MP4Box utility incorrectly handled certain AC3 files, which could lead to
    an out-of-bounds read. A remote attacker

    could use this issue to cause MP4Box to crash, resulting in a denial of service (system crash). This issue
    only affected Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2023-5520, CVE-2024-0322)

    It was discovered that the GPAC MP4Box utility incorrectly handled certain malformed text files. If a user
    or automated system using MP4Box were tricked into opening a specially crafted RST file, an attacker could
    use this issue to cause a denial of service (system crash) or execute arbitrary code. (CVE-2024-0321)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7320-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0321");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpac-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgpac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgpac11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgpac12t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgpac2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgpac4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04 / 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '14.04', 'pkgname': 'gpac', 'pkgver': '0.5.0+svn4288~dfsg1-4ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'gpac-modules-base', 'pkgver': '0.5.0+svn4288~dfsg1-4ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libgpac-dev', 'pkgver': '0.5.0+svn4288~dfsg1-4ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libgpac2', 'pkgver': '0.5.0+svn4288~dfsg1-4ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'gpac', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'gpac-modules-base', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgpac-dev', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libgpac4', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'gpac', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-3ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'gpac-modules-base', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-3ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgpac-dev', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-3ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libgpac4', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-3ubuntu0.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'gpac', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-5ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'gpac-modules-base', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-5ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libgpac-dev', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-5ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libgpac4', 'pkgver': '0.5.2-426-gc5ad4e4+dfsg5-5ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'gpac', 'pkgver': '2.0.0+dfsg1-2ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'gpac-modules-base', 'pkgver': '2.0.0+dfsg1-2ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libgpac-dev', 'pkgver': '2.0.0+dfsg1-2ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libgpac11', 'pkgver': '2.0.0+dfsg1-2ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'gpac', 'pkgver': '2.2.1+dfsg1-3.1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'gpac-modules-base', 'pkgver': '2.2.1+dfsg1-3.1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libgpac-dev', 'pkgver': '2.2.1+dfsg1-3.1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libgpac12t64', 'pkgver': '2.2.1+dfsg1-3.1ubuntu0.1~esm2', 'ubuntu_pro': TRUE}
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
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gpac / gpac-modules-base / libgpac-dev / libgpac11 / libgpac12t64 / etc');
}
