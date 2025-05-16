#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7250-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214875);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id(
    "CVE-2018-18836",
    "CVE-2018-18837",
    "CVE-2018-18838",
    "CVE-2023-22497",
    "CVE-2024-23722",
    "CVE-2024-34250",
    "CVE-2024-34251"
  );
  script_xref(name:"USN", value:"7250-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.10 : Netdata vulnerabilities (USN-7250-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7250-1 advisory.

    It was discovered that Netdata incorrectly handled parsing JSON input, which could lead to a JSON
    injection. An attacker could possibly use this issue to execute arbitrary code. This issue only affected

    Ubuntu 18.04 LTS. (CVE-2018-18836)

    It was discovered that Netdata incorrectly handled parsing HTTP headers, which could lead to a HTTP header
    injection. An attacker could possibly use this issue to cause a denial of service or leak sensitive
    information. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-18837)

    It was discovered that Netdata incorrectly handled parsing URLs, which could lead to a log injection. An
    attacker could possibly use this issue to consume system resources, resulting in a denial of service. This
    issue only affected Ubuntu 18.04 LTS. (CVE-2018-18838)

    It was discovered Netdata improperly authenticated API keys. An attacker could possibly use this issue to
    leak sensitive information or execute arbitrary code. This issue only affected Ubuntu 20.04 LTS and

    Ubuntu 22.04 LTS. (CVE-2023-22497)

    It was discovered Fluent Bit, vendored in Netdata, incorrectly handled parsing HTTP payloads. An attacker
    could possibly use this issue to disrupt logging. This issue only affected Ubuntu 24.10. (CVE-2024-23722)

    It was discovered that WebAssembly Micro Runtime, vendored in Netdata, incorrectly handled memory. An
    attacker could possibly use this issue to cause a denial of service. This issue only affected Ubuntu
    24.10. (CVE-2024-34250, CVE-2024-34251)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7250-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18837");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-22497");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netdata-apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netdata-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netdata-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netdata-plugins-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netdata-plugins-nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netdata-plugins-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netdata-web");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'netdata', 'pkgver': '1.9.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'netdata-data', 'pkgver': '1.9.0+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'netdata', 'pkgver': '1.19.0-3ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'netdata-apache2', 'pkgver': '1.19.0-3ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'netdata-core', 'pkgver': '1.19.0-3ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'netdata-plugins-bash', 'pkgver': '1.19.0-3ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'netdata-plugins-nodejs', 'pkgver': '1.19.0-3ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'netdata-plugins-python', 'pkgver': '1.19.0-3ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'netdata-web', 'pkgver': '1.19.0-3ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'netdata', 'pkgver': '1.33.1-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'netdata-apache2', 'pkgver': '1.33.1-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'netdata-core', 'pkgver': '1.33.1-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'netdata-plugins-bash', 'pkgver': '1.33.1-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'netdata-plugins-nodejs', 'pkgver': '1.33.1-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'netdata-plugins-python', 'pkgver': '1.33.1-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'netdata-web', 'pkgver': '1.33.1-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.10', 'pkgname': 'netdata', 'pkgver': '1.44.3-2ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'netdata-apache2', 'pkgver': '1.44.3-2ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'netdata-core', 'pkgver': '1.44.3-2ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'netdata-plugins-bash', 'pkgver': '1.44.3-2ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'netdata-plugins-python', 'pkgver': '1.44.3-2ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'netdata-web', 'pkgver': '1.44.3-2ubuntu0.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'netdata / netdata-apache2 / netdata-core / netdata-data / etc');
}
