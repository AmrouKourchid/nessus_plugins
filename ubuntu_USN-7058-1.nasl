#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7058-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208306);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2024-38229",
    "CVE-2024-43483",
    "CVE-2024-43484",
    "CVE-2024-43485"
  );
  script_xref(name:"USN", value:"7058-1");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS : .NET vulnerabilities (USN-7058-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-7058-1 advisory.

    Brennan Conroy discovered that the .NET Kestrel web server did not properly handle closing HTTP/3 streams
    under certain circumstances. An attacker could possibly use this issue to achieve remote code execution.
    This vulnerability only impacted .NET8. (CVE-2024-38229)

    It was discovered that .NET components designed to process malicious input were susceptible to hash
    flooding attacks. An attacker could possibly use this issue to cause a denial of service, resulting in a
    crash. (CVE-2024-43483)

    It was discovered that the .NET System.IO.Packaging namespace did not properly process SortedList data
    structures. An attacker could possibly use this issue to cause a denial of service, resulting in a crash.
    (CVE-2024-43484)

    It was discovered that .NET did not properly handle the deserialization of of certain JSON properties. An
    attacker could possibly use this issue to cause a denial of service, resulting in a crash.
    (CVE-2024-43485)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7058-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:aspnetcore-runtime-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:aspnetcore-runtime-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:aspnetcore-runtime-dbg-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:aspnetcore-targeting-pack-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:aspnetcore-targeting-pack-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-apphost-pack-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-apphost-pack-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-host-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-hostfxr-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-hostfxr-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-runtime-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-runtime-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-runtime-dbg-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-sdk-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-sdk-6.0-source-built-artifacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-sdk-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-sdk-8.0-source-built-artifacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-sdk-dbg-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-targeting-pack-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-targeting-pack-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-templates-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet-templates-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dotnet8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netstandard-targeting-pack-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:netstandard-targeting-pack-2.1-8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'aspnetcore-runtime-6.0', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'aspnetcore-runtime-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'aspnetcore-runtime-dbg-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'aspnetcore-targeting-pack-6.0', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'aspnetcore-targeting-pack-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-apphost-pack-6.0', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-apphost-pack-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-host', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-host-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-hostfxr-6.0', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-hostfxr-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-runtime-6.0', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-runtime-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-runtime-dbg-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-sdk-6.0', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-sdk-6.0-source-built-artifacts', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-sdk-8.0', 'pkgver': '8.0.110-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-sdk-8.0-source-built-artifacts', 'pkgver': '8.0.110-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-sdk-dbg-8.0', 'pkgver': '8.0.110-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-targeting-pack-6.0', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-targeting-pack-8.0', 'pkgver': '8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-templates-6.0', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet-templates-8.0', 'pkgver': '8.0.110-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet6', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'dotnet8', 'pkgver': '8.0.110-8.0.10-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'netstandard-targeting-pack-2.1', 'pkgver': '6.0.135-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'netstandard-targeting-pack-2.1-8.0', 'pkgver': '8.0.110-0ubuntu1~22.04.1'},
    {'osver': '24.04', 'pkgname': 'aspnetcore-runtime-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'aspnetcore-runtime-dbg-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'aspnetcore-targeting-pack-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-apphost-pack-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-host-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-hostfxr-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-runtime-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-runtime-dbg-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-sdk-8.0', 'pkgver': '8.0.110-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-sdk-8.0-source-built-artifacts', 'pkgver': '8.0.110-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-sdk-dbg-8.0', 'pkgver': '8.0.110-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-targeting-pack-8.0', 'pkgver': '8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet-templates-8.0', 'pkgver': '8.0.110-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'dotnet8', 'pkgver': '8.0.110-8.0.10-0ubuntu1~24.04.1'},
    {'osver': '24.04', 'pkgname': 'netstandard-targeting-pack-2.1-8.0', 'pkgver': '8.0.110-0ubuntu1~24.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aspnetcore-runtime-6.0 / aspnetcore-runtime-8.0 / etc');
}
