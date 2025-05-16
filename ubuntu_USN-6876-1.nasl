#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6876-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201892);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2019-19907", "CVE-2022-26562");
  script_xref(name:"USN", value:"6876-1");
  script_xref(name:"IAVB", value:"2024-B-0084-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Kopano Core vulnerabilities (USN-6876-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6876-1 advisory.

    It was discovered that Kopano Core allowed out-of-bounds access. An attacker could use this issue to
    expose private information. This issue only affected Ubuntu 18.04 LTS. (CVE-2019-19907)

    It was discovered that Kopano Core allowed possible authentication with expired passwords. An attacker
    could use this issue to bypass authentication. (CVE-2022-26562)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6876-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26562");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-archiver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-contacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-dagent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-ical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-presence");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-spamd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-spooler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopano-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.1-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-kopano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-kopano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-mapi");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'kopano-archiver', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-backup', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-common', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-contacts', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-core', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-dagent', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-dev', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-gateway', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-ical', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-l10n', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-libs', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-monitor', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-presence', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-search', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-server', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-spooler', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'kopano-utils', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php-mapi', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'php7.1-mapi', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python-kopano', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python-mapi', 'pkgver': '8.5.5-0ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'kopano-archiver', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-backup', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-common', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-contacts', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-core', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-dagent', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-dev', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-gateway', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-ical', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-l10n', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-libs', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-monitor', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-presence', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-search', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-server', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-spamd', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-spooler', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'kopano-utils', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'php-mapi', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-kopano', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-mapi', 'pkgver': '8.7.0-7ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-archiver', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-backup', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-common', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-contacts', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-core', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-dagent', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-dev', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-gateway', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-ical', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-l10n', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-libs', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-monitor', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-presence', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-search', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-server', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-spamd', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-spooler', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'kopano-utils', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'php-mapi', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-kopano', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-mapi', 'pkgver': '8.7.0-7.1ubuntu10.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kopano-archiver / kopano-backup / kopano-common / kopano-contacts / etc');
}
