#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5882-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171810);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-8979",
    "CVE-2019-1010228",
    "CVE-2021-41687",
    "CVE-2021-41688",
    "CVE-2021-41689",
    "CVE-2021-41690",
    "CVE-2022-2119",
    "CVE-2022-2120",
    "CVE-2022-2121",
    "CVE-2022-43272"
  );
  script_xref(name:"USN", value:"5882-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM : DCMTK vulnerabilities (USN-5882-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5882-1 advisory.

    Gjoko Krstic discovered that DCMTK incorrectly handled buffers. If a user or an automated system were
    tricked into opening a certain specially crafted

    input file, a remote attacker could possibly use this issue to cause a

    denial of service. This issue only affected Ubuntu 16.04 LTS. (CVE-2015-8979)

    Omar Ganiev discovered that DCMTK incorrectly handled buffers. If a user or an automated system were
    tricked into opening a certain specially crafted

    input file, a remote attacker could possibly use this issue to cause a

    denial of service. This issue only affected Ubuntu 16.04 LTS and

    Ubuntu 18.04 LTS. (CVE-2019-1010228)

    Jinsheng Ba discovered that DCMTK incorrectly handled certain requests. If a user or an automated system
    were tricked into opening a certain specially crafted input file, a remote attacker could possibly use
    this issue to

    cause a denial of service. This issue only affected Ubuntu 16.04 LTS,

    Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2021-41687, CVE-2021-41688, CVE-2021-41689,
    and CVE-2021-41690)

    Sharon Brizinov and Noam Moshe discovered that DCMTK incorrectly handled certain inputs. If a user or an
    automated system were tricked into opening a certain specially crafted input file, a remote attacker could
    possibly use this issue to execute arbitrary code. This issue only affected

    Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-2119 and
    CVE-2022-2120)

    Sharon Brizinov and Noam Moshe discovered that DCMTK incorrectly handled pointers. If a user or an
    automated system were tricked into opening a certain specially crafted input file, a remote attacker could
    possibly use this issue to cause a denial of service. This issue only affected Ubuntu 16.04 LTS, Ubuntu
    18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-2121)

    It was discovered that DCMTK incorrectly handled certain inputs. If a user or an automated system were
    tricked into opening a certain specially crafted input file, a remote attacker could possibly use this
    issue to

    cause a denial of service. This issue affected Ubuntu 16.04 LTS,

    Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 22.10. (CVE-2022-43272)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5882-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2120");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dcmtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdcmtk5");
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
    {'osver': '16.04', 'pkgname': 'dcmtk', 'pkgver': '3.6.1~20150924-5ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.1~20150924-5ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libdcmtk5', 'pkgver': '3.6.1~20150924-5ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'dcmtk', 'pkgver': '3.6.2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libdcmtk12', 'pkgver': '3.6.2-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'dcmtk', 'pkgver': '3.6.4-2.1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.4-2.1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libdcmtk14', 'pkgver': '3.6.4-2.1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'dcmtk', 'pkgver': '3.6.6-5ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libdcmtk-dev', 'pkgver': '3.6.6-5ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libdcmtk16', 'pkgver': '3.6.6-5ubuntu0.1~esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dcmtk / libdcmtk-dev / libdcmtk12 / libdcmtk14 / libdcmtk16 / etc');
}
