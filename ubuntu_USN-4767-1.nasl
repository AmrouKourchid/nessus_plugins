#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4767-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183641);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-3005",
    "CVE-2016-4338",
    "CVE-2016-10134",
    "CVE-2016-10742",
    "CVE-2017-2824",
    "CVE-2017-2825",
    "CVE-2019-15132",
    "CVE-2020-11800",
    "CVE-2020-15803"
  );
  script_xref(name:"USN", value:"4767-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM : Zabbix vulnerabilities (USN-4767-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4767-1 advisory.

    Fu Chuang discovered that Zabbix did not properly parse IPs. A remote attacker could possibly use this
    issue to execute arbitrary code. This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and Ubuntu
    18.04 ESM. (CVE-2020-11800)

    It was discovered that Zabbix incorrectly handled certain requests. A remote attacker could possibly use
    this issue to execute arbitrary code. This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
    (CVE-2017-2824, CVE-2017-2825)

    It was discovered that Zabbix incorrectly handled certain XML files. A remote attacker could possibly use
    this issue to read arbitrary files or potentially execute arbitrary code. This issue only affected Ubuntu
    14.04 ESM. (CVE-2014-3005)

    It was discovered that Zabbix incorrectly handled certain inputs. A remote attacker could possibly use
    this issue to execute arbitrary SQL commands. This issue only affected Ubuntu 14.04 ESM. (CVE-2016-10134,
    CVE-2016-4338)

    It was discovered that Zabbix incorrectly handled the request parameter. A remote attacker could possibly
    use this issue to redirect requests to external links. This issue only affected Ubuntu 14.04 ESM and
    Ubuntu 18.04 ESM. (CVE-2016-10742)

    It was discovered that Zabbix incorrectly handled failed login attempts. A remote attacker could possibly
    use this issue to enumerate users. (CVE-2019-15132)

    It was discovered that Zabbix did not properly validate input. A remote attacker could exploit this to
    conduct cross-site scripting (XSS) attacks. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM
    and Ubuntu 20.04 ESM. (CVE-2020-15803)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4767-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11800");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zabbix-frontend-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zabbix-java-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zabbix-proxy-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zabbix-proxy-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zabbix-proxy-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zabbix-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zabbix-server-pgsql");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'zabbix-agent', 'pkgver': '1:2.4.7+dfsg-2ubuntu2.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'zabbix-frontend-php', 'pkgver': '1:2.4.7+dfsg-2ubuntu2.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'zabbix-java-gateway', 'pkgver': '1:2.4.7+dfsg-2ubuntu2.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'zabbix-proxy-mysql', 'pkgver': '1:2.4.7+dfsg-2ubuntu2.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'zabbix-proxy-pgsql', 'pkgver': '1:2.4.7+dfsg-2ubuntu2.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'zabbix-proxy-sqlite3', 'pkgver': '1:2.4.7+dfsg-2ubuntu2.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'zabbix-server-mysql', 'pkgver': '1:2.4.7+dfsg-2ubuntu2.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'zabbix-server-pgsql', 'pkgver': '1:2.4.7+dfsg-2ubuntu2.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'zabbix-agent', 'pkgver': '1:3.0.12+dfsg-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'zabbix-frontend-php', 'pkgver': '1:3.0.12+dfsg-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'zabbix-java-gateway', 'pkgver': '1:3.0.12+dfsg-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'zabbix-proxy-mysql', 'pkgver': '1:3.0.12+dfsg-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'zabbix-proxy-pgsql', 'pkgver': '1:3.0.12+dfsg-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'zabbix-proxy-sqlite3', 'pkgver': '1:3.0.12+dfsg-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'zabbix-server-mysql', 'pkgver': '1:3.0.12+dfsg-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'zabbix-server-pgsql', 'pkgver': '1:3.0.12+dfsg-1ubuntu0.1~esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'zabbix-agent', 'pkgver': '1:4.0.17+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'zabbix-frontend-php', 'pkgver': '1:4.0.17+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'zabbix-java-gateway', 'pkgver': '1:4.0.17+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'zabbix-proxy-mysql', 'pkgver': '1:4.0.17+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'zabbix-proxy-pgsql', 'pkgver': '1:4.0.17+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'zabbix-proxy-sqlite3', 'pkgver': '1:4.0.17+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'zabbix-server-mysql', 'pkgver': '1:4.0.17+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'zabbix-server-pgsql', 'pkgver': '1:4.0.17+dfsg-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'zabbix-agent / zabbix-frontend-php / zabbix-java-gateway / etc');
}
