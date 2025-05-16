#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7027-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207478);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/19");

  script_cve_id(
    "CVE-2022-45939",
    "CVE-2022-48337",
    "CVE-2022-48338",
    "CVE-2022-48339",
    "CVE-2023-28617",
    "CVE-2024-30203",
    "CVE-2024-30204",
    "CVE-2024-30205",
    "CVE-2024-39331"
  );
  script_xref(name:"IAVA", value:"2024-A-0247-S");
  script_xref(name:"IAVA", value:"2024-A-0368");
  script_xref(name:"USN", value:"7027-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS : Emacs vulnerabilities (USN-7027-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-7027-1 advisory.

    It was discovered that Emacs incorrectly handled input sanitization. An attacker could possibly use this
    issue to execute arbitrary commands. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and
    Ubuntu 22.04 LTS. (CVE-2022-45939)

    Xi Lu discovered that Emacs incorrectly handled input sanitization. An attacker could possibly use this
    issue to execute arbitrary commands. This issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu
    20.04 LTS and Ubuntu 22.04 LTS. (CVE-2022-48337)

    Xi Lu discovered that Emacs incorrectly handled input sanitization. An attacker could possibly use this
    issue to execute arbitrary commands. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-48338)

    Xi Lu discovered that Emacs incorrectly handled input sanitization. An attacker could possibly use this
    issue to execute arbitrary commands. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and
    Ubuntu 22.04 LTS. (CVE-2022-48339)

    It was discovered that Emacs incorrectly handled filename sanitization. An attacker could possibly use
    this issue to execute arbitrary commands. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and
    Ubuntu 22.04 LTS. (CVE-2023-28617)

    It was discovered that Emacs incorrectly handled certain crafted files. An attacker could possibly use
    this issue to crash the program, resulting in a denial of service. This issue only affected Ubuntu 16.04
    LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2024-30203, CVE-2024-30204,
    CVE-2024-30205)

    It was discovered that Emacs incorrectly handled certain crafted files. An attacker could possibly use
    this issue to execute arbitrary commands. (CVE-2024-39331)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7027-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-pgtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs24-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs24-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs24-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs24-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs24-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs25-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs25-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs25-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs25-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs25-nox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'emacs24', 'pkgver': '24.5+1-6ubuntu1.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'emacs24-bin-common', 'pkgver': '24.5+1-6ubuntu1.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'emacs24-common', 'pkgver': '24.5+1-6ubuntu1.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'emacs24-el', 'pkgver': '24.5+1-6ubuntu1.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'emacs24-lucid', 'pkgver': '24.5+1-6ubuntu1.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'emacs24-nox', 'pkgver': '24.5+1-6ubuntu1.1+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'emacs25', 'pkgver': '25.2+1-6ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'emacs25-bin-common', 'pkgver': '25.2+1-6ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'emacs25-common', 'pkgver': '25.2+1-6ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'emacs25-el', 'pkgver': '25.2+1-6ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'emacs25-lucid', 'pkgver': '25.2+1-6ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'emacs25-nox', 'pkgver': '25.2+1-6ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'emacs', 'pkgver': '1:26.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'emacs-bin-common', 'pkgver': '1:26.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'emacs-common', 'pkgver': '1:26.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'emacs-el', 'pkgver': '1:26.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'emacs-gtk', 'pkgver': '1:26.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'emacs-lucid', 'pkgver': '1:26.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'emacs-nox', 'pkgver': '1:26.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'emacs', 'pkgver': '1:27.1+1-3ubuntu5.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'emacs-bin-common', 'pkgver': '1:27.1+1-3ubuntu5.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'emacs-common', 'pkgver': '1:27.1+1-3ubuntu5.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'emacs-el', 'pkgver': '1:27.1+1-3ubuntu5.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'emacs-gtk', 'pkgver': '1:27.1+1-3ubuntu5.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'emacs-lucid', 'pkgver': '1:27.1+1-3ubuntu5.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'emacs-nox', 'pkgver': '1:27.1+1-3ubuntu5.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'emacs', 'pkgver': '1:29.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'emacs-bin-common', 'pkgver': '1:29.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'emacs-common', 'pkgver': '1:29.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'emacs-el', 'pkgver': '1:29.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'emacs-gtk', 'pkgver': '1:29.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'emacs-lucid', 'pkgver': '1:29.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'emacs-nox', 'pkgver': '1:29.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'emacs-pgtk', 'pkgver': '1:29.3+1-1ubuntu2+esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'emacs / emacs-bin-common / emacs-common / emacs-el / emacs-gtk / etc');
}
