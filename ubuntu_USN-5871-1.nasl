#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5871-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171483);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2023-22490", "CVE-2023-23946");
  script_xref(name:"USN", value:"5871-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS : Git vulnerabilities (USN-5871-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5871-1 advisory.

    It was discovered that Git incorrectly handled certain repositories. An attacker could use this issue to
    make Git uses its local clone optimization even when using a non-local transport. (CVE-2023-22490)

    Joern Schneeweisz discovered that Git incorrectly handled certain commands. An attacker could possibly use
    this issue to overwrite a patch outside the working tree. (CVE-2023-23946)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5871-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-daemon-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-daemon-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gitweb");
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
    {'osver': '16.04', 'pkgname': 'git', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-all', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-arch', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-core', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-el', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-email', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-gui', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-man', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'git-svn', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'gitk', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'gitweb', 'pkgver': '1:2.7.4-0ubuntu1.10+esm5', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'git', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-all', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-el', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-email', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-gui', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-man', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'git-svn', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'gitk', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'gitweb', 'pkgver': '1:2.17.1-1ubuntu0.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-all', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-el', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-email', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-gui', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-man', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'git-svn', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'gitk', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'gitweb', 'pkgver': '1:2.25.1-1ubuntu3.10', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-all', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-cvs', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-daemon-run', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-daemon-sysvinit', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-email', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-gui', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-man', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-mediawiki', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'git-svn', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'gitk', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'gitweb', 'pkgver': '1:2.34.1-1ubuntu1.8', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git / git-all / git-arch / git-core / git-cvs / git-daemon-run / etc');
}
