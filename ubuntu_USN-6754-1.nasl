#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6754-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193905);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2019-9511",
    "CVE-2019-9513",
    "CVE-2023-44487",
    "CVE-2024-28182"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"USN", value:"6754-1");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 : nghttp2 vulnerabilities (USN-6754-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6754-1 advisory.

    It was discovered that nghttp2 incorrectly handled the HTTP/2 implementation. A remote attacker could
    possibly use this issue to cause nghttp2 to consume resources, leading to a denial of service. This issue
    only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-9511, CVE-2019-9513)

    It was discovered that nghttp2 incorrectly handled request cancellation. A remote attacker could possibly
    use this issue to cause nghttp2 to consume resources, leading to a denial of service. This issue only
    affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2023-44487)

    It was discovered that nghttp2 could be made to process an unlimited number of HTTP/2 CONTINUATION frames.
    A remote attacker could possibly use this issue to cause nghttp2 to consume resources, leading to a denial
    of service. (CVE-2024-28182)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6754-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9513");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-44487");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnghttp2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnghttp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nghttp2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nghttp2-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nghttp2-server");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libnghttp2-14', 'pkgver': '1.7.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libnghttp2-dev', 'pkgver': '1.7.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nghttp2', 'pkgver': '1.7.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nghttp2-client', 'pkgver': '1.7.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nghttp2-proxy', 'pkgver': '1.7.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nghttp2-server', 'pkgver': '1.7.1-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libnghttp2-14', 'pkgver': '1.30.0-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libnghttp2-dev', 'pkgver': '1.30.0-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'nghttp2', 'pkgver': '1.30.0-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'nghttp2-client', 'pkgver': '1.30.0-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'nghttp2-proxy', 'pkgver': '1.30.0-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'nghttp2-server', 'pkgver': '1.30.0-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libnghttp2-14', 'pkgver': '1.40.0-1ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libnghttp2-dev', 'pkgver': '1.40.0-1ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nghttp2', 'pkgver': '1.40.0-1ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nghttp2-client', 'pkgver': '1.40.0-1ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nghttp2-proxy', 'pkgver': '1.40.0-1ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nghttp2-server', 'pkgver': '1.40.0-1ubuntu0.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libnghttp2-14', 'pkgver': '1.43.0-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libnghttp2-dev', 'pkgver': '1.43.0-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'nghttp2', 'pkgver': '1.43.0-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'nghttp2-client', 'pkgver': '1.43.0-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'nghttp2-proxy', 'pkgver': '1.43.0-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'nghttp2-server', 'pkgver': '1.43.0-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libnghttp2-14', 'pkgver': '1.55.1-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libnghttp2-dev', 'pkgver': '1.55.1-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'nghttp2', 'pkgver': '1.55.1-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'nghttp2-client', 'pkgver': '1.55.1-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'nghttp2-proxy', 'pkgver': '1.55.1-1ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'nghttp2-server', 'pkgver': '1.55.1-1ubuntu0.2', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnghttp2-14 / libnghttp2-dev / nghttp2 / nghttp2-client / etc');
}
