#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6452-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183889);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-3896",
    "CVE-2023-4733",
    "CVE-2023-4734",
    "CVE-2023-4735",
    "CVE-2023-4738",
    "CVE-2023-4750",
    "CVE-2023-4751",
    "CVE-2023-4752",
    "CVE-2023-4781",
    "CVE-2023-5344",
    "CVE-2023-5441",
    "CVE-2023-5535"
  );
  script_xref(name:"IAVB", value:"2023-B-0066-S");
  script_xref(name:"IAVB", value:"2023-B-0074-S");
  script_xref(name:"USN", value:"6452-1");
  script_xref(name:"IAVB", value:"2023-B-0084-S");
  script_xref(name:"IAVA", value:"2023-A-0579-S");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : Vim vulnerabilities (USN-6452-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-6452-1 advisory.

    It was discovered that Vim could be made to divide by zero. An attacker could possibly use this issue to
    cause a denial of service. This issue only affected Ubuntu 23.04. (CVE-2023-3896)

    It was discovered that Vim did not properly manage memory. An attacker could possibly use this issue to
    cause a denial of service or execute arbitrary code. (CVE-2023-4733, CVE-2023-4750)

    It was discovered that Vim contained an arithmetic overflow. An attacker could possibly use this issue to
    cause a denial of service. This issue only affected Ubuntu 22.04 LTS, Ubuntu 23.04, and Ubuntu 23.10.
    (CVE-2023-4734)

    It was discovered that Vim could be made to write out of bounds. An attacker could possibly use this issue
    to cause a denial of service or execute arbitrary code. (CVE-2023-4735, CVE-2023-5344)

    It was discovered that Vim could be made to write out of bounds. An attacker could possibly use this issue
    to cause a denial of service or execute arbitrary code. This issue only affected Ubuntu 23.04 and Ubuntu
    23.10. (CVE-2023-4738)

    It was discovered that Vim could be made to write out of bounds. An attacker could possibly use this issue
    to cause a denial of service or execute arbitrary code. This issue only affected Ubuntu 14.04 LTS, Ubuntu
    16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 23.04. (CVE-2023-4751)

    It was discovered that Vim did not properly manage memory. An attacker could possibly use this issue to
    cause a denial of service or execute arbitrary code. This issue only affected Ubuntu 20.04 LTS, Ubuntu
    22.04 LTS, Ubuntu 23.04, and Ubuntu 23.10. (CVE-2023-4752, CVE-2023-5535)

    It was discovered that Vim could be made to write out of bounds. An attacker could possibly use this issue
    to cause a denial of service or execute arbitrary code. This issue only affected Ubuntu 20.04 LTS, Ubuntu
    22.04 LTS, Ubuntu 23.04, and Ubuntu 23.10. (CVE-2023-4781)

    It was discovered that Vim could be made to dereference invalid memory. An attacker could possibly use
    this issue to cause a denial of service. (CVE-2023-5441)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6452-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5535");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-athena-py2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gnome-py2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk-py2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk3-py2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-lesstif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-motif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-nox-py2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xxd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'vim', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-athena', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-athena-py2', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-common', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-gnome', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-gnome-py2', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-gtk', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-gtk-py2', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-gtk3-py2', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-nox', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-nox-py2', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-runtime', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'vim-tiny', 'pkgver': '2:7.4.1689-3ubuntu1.5+esm20', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-athena', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-common', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-gnome', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-gtk', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-nox', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-runtime', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'vim-tiny', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'xxd', 'pkgver': '2:8.0.1453-1ubuntu1.13+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'vim', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'vim-athena', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'vim-common', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'vim-gtk', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'vim-nox', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'vim-runtime', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'vim-tiny', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'xxd', 'pkgver': '2:8.1.2269-1ubuntu5.20', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim-athena', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim-common', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim-gtk', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim-nox', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim-runtime', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'vim-tiny', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'xxd', 'pkgver': '2:8.2.3995-1ubuntu2.13', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim-athena', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim-common', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim-motif', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim-nox', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim-runtime', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'vim-tiny', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'xxd', 'pkgver': '2:9.0.1000-4ubuntu3.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim-athena', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim-common', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim-gtk3', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim-gui-common', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim-motif', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim-nox', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim-runtime', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'vim-tiny', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'xxd', 'pkgver': '2:9.0.1672-1ubuntu2.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-athena-py2 / vim-common / vim-gnome / etc');
}
