#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6695-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192119);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2019-18604", "CVE-2023-32668", "CVE-2024-25262");
  script_xref(name:"USN", value:"6695-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 : TeX Live vulnerabilities (USN-6695-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6695-1 advisory.

    It was discovered that TeX Live incorrectly handled certain memory operations in the embedded axodraw2
    tool. An attacker could possibly use this issue to cause TeX Live to crash, resulting in a denial of
    service. This issue only affected Ubuntu 20.04 LTS. (CVE-2019-18604)

    It was discovered that TeX Live allowed documents to make arbitrary network requests. If a user or
    automated system were tricked into opening a specially crafted document, a remote attacker could possibly
    use this issue to exfiltrate sensitive information, or perform other network-related attacks. This issue
    only affected Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2023-32668)

    It was discovered that TeX Live incorrectly handled certain TrueType fonts. If a user or automated system
    were tricked into opening a specially crafted TrueType font, a remote attacker could use this issue to
    cause TeX Live to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2024-25262)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6695-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libptexenc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libptexenc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsynctex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsynctex2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua53-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua53-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexluajit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexluajit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-binaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-binaries-sse2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libkpathsea-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libkpathsea6', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libptexenc-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libptexenc1', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsynctex-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libsynctex2', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libtexlua53', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libtexlua53-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libtexluajit-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libtexluajit2', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'texlive-binaries', 'pkgver': '2019.20190605.51237-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libkpathsea-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libkpathsea6', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libptexenc-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libptexenc1', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsynctex-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libsynctex2', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtexlua53', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtexlua53-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtexluajit-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtexluajit2', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'texlive-binaries', 'pkgver': '2021.20210626.59705-1ubuntu0.2'},
    {'osver': '23.10', 'pkgname': 'libkpathsea-dev', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libkpathsea6', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libptexenc-dev', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libptexenc1', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libsynctex-dev', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libsynctex2', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libtexlua-dev', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libtexlua53', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libtexlua53-5', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libtexlua53-dev', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libtexluajit-dev', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'libtexluajit2', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'texlive-binaries', 'pkgver': '2023.20230311.66589-6ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'texlive-binaries-sse2', 'pkgver': '2023.20230311.66589-6ubuntu0.1'}
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
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libkpathsea-dev / libkpathsea6 / libptexenc-dev / libptexenc1 / etc');
}
