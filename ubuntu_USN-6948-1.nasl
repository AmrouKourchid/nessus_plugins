#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6948-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205228);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-16846",
    "CVE-2020-17490",
    "CVE-2020-25592",
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-3148",
    "CVE-2021-3197",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"USN", value:"6948-1");
  script_xref(name:"CEA-ID", value:"CEA-2020-0134");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Salt vulnerabilities (USN-6948-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6948-1 advisory.

    It was discovered that Salt incorrectly handled crafted web requests. A remote attacker could possibly use
    this issue to run arbitrary commands. (CVE-2020-16846)

    It was discovered that Salt incorrectly created certificates with weak file permissions. (CVE-2020-17490)

    It was discovered that Salt incorrectly handled credential validation. A remote attacker could possibly
    use this issue to bypass authentication. (CVE-2020-25592)

    It was discovered that Salt incorrectly handled crafted process names. An attacker could possibly use this
    issue to run arbitrary commands. This issue only affected Ubuntu 18.04 LTS. (CVE-2020-28243)

    It was discovered that Salt incorrectly handled validation of SSL/TLS certificates. A remote attacker
    could possibly use this issue to spoof a trusted entity. (CVE-2020-28972, CVE-2020-35662)

    It was discovered that Salt incorrectly handled credential validation. A remote attacker could possibly
    use this issue to run arbitrary code. (CVE-2021-25281)

    It was discovered that Salt incorrectly handled crafted paths. A remote attacker could possibly use this
    issue to perform directory traversal. (CVE-2021-25282)

    It was discovered that Salt incorrectly handled template rendering. A remote attacker could possibly this
    issue to run arbitrary code. (CVE-2021-25283)

    It was discovered that Salt incorrectly handled logging. An attacker could possibly use this issue to
    discover credentials. This issue only affected Ubuntu 18.04 LTS. (CVE-2021-25284)

    It was discovered that Salt incorrectly handled crafted web requests. A remote attacker could possibly use
    this issue to run arbitrary commands. This issue only affected Ubuntu 18.04 LTS. (CVE-2021-3148)

    It was discovered that Salt incorrectly handled input sanitization. A remote attacker could possibly use
    this issue to run arbitrary commands. (CVE-2021-3197)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6948-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt REST API Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:salt-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:salt-syndic");
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
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'salt-api', 'pkgver': '2015.8.8+ds-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'salt-cloud', 'pkgver': '2015.8.8+ds-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'salt-common', 'pkgver': '2015.8.8+ds-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'salt-master', 'pkgver': '2015.8.8+ds-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'salt-minion', 'pkgver': '2015.8.8+ds-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'salt-proxy', 'pkgver': '2015.8.8+ds-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'salt-ssh', 'pkgver': '2015.8.8+ds-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'salt-syndic', 'pkgver': '2015.8.8+ds-1ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'salt-api', 'pkgver': '2017.7.4+dfsg1-1ubuntu18.04.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'salt-cloud', 'pkgver': '2017.7.4+dfsg1-1ubuntu18.04.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'salt-common', 'pkgver': '2017.7.4+dfsg1-1ubuntu18.04.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'salt-master', 'pkgver': '2017.7.4+dfsg1-1ubuntu18.04.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'salt-minion', 'pkgver': '2017.7.4+dfsg1-1ubuntu18.04.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'salt-proxy', 'pkgver': '2017.7.4+dfsg1-1ubuntu18.04.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'salt-ssh', 'pkgver': '2017.7.4+dfsg1-1ubuntu18.04.2+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'salt-syndic', 'pkgver': '2017.7.4+dfsg1-1ubuntu18.04.2+esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'salt-api / salt-cloud / salt-common / salt-master / salt-minion / etc');
}
