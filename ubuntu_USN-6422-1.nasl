#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6422-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182792);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2021-37706",
    "CVE-2021-43299",
    "CVE-2021-43300",
    "CVE-2021-43301",
    "CVE-2021-43302",
    "CVE-2021-43303",
    "CVE-2021-43804",
    "CVE-2021-43845",
    "CVE-2022-21722",
    "CVE-2022-21723",
    "CVE-2022-23537",
    "CVE-2022-23547",
    "CVE-2022-23608",
    "CVE-2022-24754",
    "CVE-2022-24763",
    "CVE-2022-24764",
    "CVE-2022-24793",
    "CVE-2022-31031",
    "CVE-2022-39244",
    "CVE-2023-27585"
  );
  script_xref(name:"USN", value:"6422-1");

  script_name(english:"Ubuntu 18.04 ESM / 20.04 LTS / 23.04 : Ring vulnerabilities (USN-6422-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 ESM / 20.04 LTS / 23.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6422-1 advisory.

    It was discovered that Ring incorrectly handled certain inputs. If a user or an automated system were
    tricked into opening a specially crafted input file, a remote attacker could possibly use this issue to
    execute arbitrary code. (CVE-2021-37706)

    It was discovered that Ring incorrectly handled certain inputs. If a user or an automated system were
    tricked into opening a specially crafted input file, a remote attacker could possibly use this issue to
    cause a denial of service. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.

    (CVE-2021-43299, CVE-2021-43300, CVE-2021-43301, CVE-2021-43302,

    CVE-2021-43303, CVE-2021-43804, CVE-2021-43845, CVE-2022-21723,

    CVE-2022-23537, CVE-2022-23547, CVE-2022-23608, CVE-2022-24754, CVE-2022-24763, CVE-2022-24764,
    CVE-2022-24793, CVE-2022-31031, CVE-2022-39244)

    It was discovered that Ring incorrectly handled certain inputs. If a user or an automated system were
    tricked into opening a specially crafted input file, a remote attacker could possibly use this issue to
    cause a denial of service. This issue only affected Ubuntu 20.04 LTS. (CVE-2022-21722)

    It was discovered that Ring incorrectly handled certain inputs. If a user or an automated system were
    tricked into opening a specially crafted input file, a remote attacker could possibly use this issue to
    cause a denial of service. (CVE-2023-27585)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6422-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37706");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39244");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:jami");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:jami-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ring-daemon");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'ring', 'pkgver': '20180228.1.503da2b~ds1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ring-daemon', 'pkgver': '20180228.1.503da2b~ds1-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'jami', 'pkgver': '20190215.1.f152c98~ds1-1+deb10u2build0.20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'jami-daemon', 'pkgver': '20190215.1.f152c98~ds1-1+deb10u2build0.20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ring', 'pkgver': '20190215.1.f152c98~ds1-1+deb10u2build0.20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ring-daemon', 'pkgver': '20190215.1.f152c98~ds1-1+deb10u2build0.20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'jami', 'pkgver': '20230206.0~ds1-5ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'jami-daemon', 'pkgver': '20230206.0~ds1-5ubuntu0.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jami / jami-daemon / ring / ring-daemon');
}
