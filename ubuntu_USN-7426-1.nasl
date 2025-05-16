#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7426-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234054);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2025-32364", "CVE-2025-32365");
  script_xref(name:"USN", value:"7426-1");
  script_xref(name:"IAVB", value:"2025-B-0050-S");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : poppler vulnerabilities (USN-7426-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7426-1 advisory.

    It was discovered that poppler incorrectly handled memory when opening certain PDF files. An attacker
    could possibly use this issue to cause poppler to crash, resulting in a denial of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7426-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32365");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-poppler-0.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp0v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib8t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-1t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt6-3t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler-cpp0v5', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler-dev', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler-glib8', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler-qt5-1', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libpoppler97', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'poppler-utils', 'pkgver': '0.86.1-0ubuntu1.6'},
    {'osver': '22.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler-cpp0v5', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler-dev', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler-glib8', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler-qt5-1', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'libpoppler118', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '22.04', 'pkgname': 'poppler-utils', 'pkgver': '22.02.0-2ubuntu0.7'},
    {'osver': '24.04', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-cpp0t64', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-dev', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-glib8t64', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-private-dev', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-qt5-1t64', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-qt6-3t64', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler-qt6-dev', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'libpoppler134', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.04', 'pkgname': 'poppler-utils', 'pkgver': '24.02.0-1ubuntu9.3'},
    {'osver': '24.10', 'pkgname': 'gir1.2-poppler-0.18', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-cpp-dev', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-cpp1', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-dev', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-glib-dev', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-glib8t64', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-private-dev', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-qt5-1t64', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-qt5-dev', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-qt6-3t64', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler-qt6-dev', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'libpoppler140', 'pkgver': '24.08.0-1ubuntu0.2'},
    {'osver': '24.10', 'pkgname': 'poppler-utils', 'pkgver': '24.08.0-1ubuntu0.2'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-poppler-0.18 / libpoppler-cpp-dev / libpoppler-cpp0t64 / etc');
}
