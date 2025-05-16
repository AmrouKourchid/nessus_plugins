#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7482-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235177);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_xref(name:"USN", value:"7482-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 / 25.04 : OpenJDK 17 vulnerabilities (USN-7482-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 / 25.04 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-7482-1 advisory.

    Alicja Kario discovered that the JSSE component of OpenJDK 17 incorrectly handled RSA padding. An Attacker
    could possibly use this issue to obtain sensitive information. (CVE-2025-21587)

    It was discovered that the Compiler component of OpenJDK 17 incorrectly handled compiler transformations.
    An attacker could possibly use this issue to cause a denial of service or execute arbitrary code.
    (CVE-2025-30691)

    It was discovered that the 2D component of OpenJDK 17 did not properly manage memory under certain
    circumstances. An attacker could possibly use this issue to cause a denial of service or execute arbitrary
    code. (CVE-2025-30698)

    In addition to security fixes, the updated packages contain bug fixes, new features, and possibly
    incompatible changes.

    Please see the following for more information:
    https://openjdk.org/groups/vulnerability/advisories/2025-04-15

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7482-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:25.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-source");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release || '25.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 24.04 / 24.10 / 25.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.15+6~us1-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.15+6~us1-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.15+6~us1-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.15+6~us1-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.15+6~us1-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.15+6~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.15+6~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.15+6~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.15+6~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.15+6~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.15+6~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.15+6~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.15+6~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.15+6~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.15+6~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.15+6~us1-0ubuntu1~24.10', 'ubuntu_pro': FALSE},
    {'osver': '25.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.15+6~us1-0ubuntu1~25.04', 'ubuntu_pro': FALSE},
    {'osver': '25.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.15+6~us1-0ubuntu1~25.04', 'ubuntu_pro': FALSE},
    {'osver': '25.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~25.04', 'ubuntu_pro': FALSE},
    {'osver': '25.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.15+6~us1-0ubuntu1~25.04', 'ubuntu_pro': FALSE},
    {'osver': '25.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.15+6~us1-0ubuntu1~25.04', 'ubuntu_pro': FALSE},
    {'osver': '25.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.15+6~us1-0ubuntu1~25.04', 'ubuntu_pro': FALSE},
    {'osver': '25.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.15+6~us1-0ubuntu1~25.04', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (deb_check(release:osver, prefix:pkgname, reference:pkgver, cves:cves)) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-17-demo / openjdk-17-jdk / openjdk-17-jdk-headless / etc');
}
