#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6527-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186449);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2023-22025", "CVE-2023-22081");
  script_xref(name:"USN", value:"6527-1");

  script_name(english:"Ubuntu 18.04 ESM / 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : OpenJDK vulnerabilities (USN-6527-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 ESM / 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6527-1 advisory.

    Carter Kozak discovered that OpenJDK, when compiling with AVX-512 instruction support enabled, could
    produce code that resulted in memory corruption in certain situations. An attacker targeting applications
    built in this way could possibly use this to cause a denial of service or execute arbitrary code. In
    Ubuntu, OpenJDK defaults to not using AVX-512 instructions. (CVE-2023-22025)

    It was discovered that OpenJDK did not properly perform PKIX certification path validation in certain
    situations. An attacker could use this to cause a denial of service. (CVE-2023-22081)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6527-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-21-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-21-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-21-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-21-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-21-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-21-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-21-source");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.21+9-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.21+9-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.21+9-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.21+9-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.21+9-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.21+9-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.21+9-0ubuntu1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.9+9-1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.9+9-1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.9+9-1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.9+9-1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.9+9-1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.9+9-1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.9+9-1~18.04', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.21+9-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.21+9-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.21+9-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.21+9-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.21+9-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.21+9-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.21+9-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.9+9-1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.9+9-1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.9+9-1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.9+9-1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.9+9-1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.9+9-1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.9+9-1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.21+9-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.21+9-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.21+9-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.21+9-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.21+9-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.21+9-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.21+9-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.9+9-1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.9+9-1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.9+9-1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.9+9-1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.9+9-1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.9+9-1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.9+9-1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.21+9-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.21+9-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.21+9-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.21+9-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.21+9-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.21+9-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.21+9-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.9+9-1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.9+9-1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.9+9-1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.9+9-1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.9+9-1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.9+9-1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.9+9-1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-21-demo', 'pkgver': '21.0.1+12-2~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-21-jdk', 'pkgver': '21.0.1+12-2~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-21-jdk-headless', 'pkgver': '21.0.1+12-2~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-21-jre', 'pkgver': '21.0.1+12-2~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-21-jre-headless', 'pkgver': '21.0.1+12-2~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-21-jre-zero', 'pkgver': '21.0.1+12-2~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-21-source', 'pkgver': '21.0.1+12-2~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.21+9-0ubuntu1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.21+9-0ubuntu1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.21+9-0ubuntu1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.21+9-0ubuntu1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.21+9-0ubuntu1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.21+9-0ubuntu1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.21+9-0ubuntu1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.9+9-1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.9+9-1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.9+9-1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.9+9-1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.9+9-1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.9+9-1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.9+9-1~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-21-demo', 'pkgver': '21.0.1+12-2~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-21-jdk', 'pkgver': '21.0.1+12-2~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-21-jdk-headless', 'pkgver': '21.0.1+12-2~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-21-jre', 'pkgver': '21.0.1+12-2~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-21-jre-headless', 'pkgver': '21.0.1+12-2~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-21-jre-zero', 'pkgver': '21.0.1+12-2~23.10', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'openjdk-21-source', 'pkgver': '21.0.1+12-2~23.10', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-11-demo / openjdk-11-jdk / openjdk-11-jdk-headless / etc');
}
