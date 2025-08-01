#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5764-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168465);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-2347",
    "CVE-2022-30552",
    "CVE-2022-30767",
    "CVE-2022-30790",
    "CVE-2022-33103",
    "CVE-2022-33967",
    "CVE-2022-34835"
  );
  script_xref(name:"USN", value:"5764-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : U-Boot vulnerabilities (USN-5764-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5764-1 advisory.

    It was discovered that U-Boot incorrectly handled certain USB DFU download setup packets. A local attacker
    could use this issue to cause U-Boot to crash, resulting in a denial of service, or possibly execute
    arbitrary code. (CVE-2022-2347)

    Nicolas Bidron and Nicolas Guigo discovered that U-Boot incorrectly handled certain fragmented IP packets.
    A local attacker could use this issue to cause U-Boot to crash, resulting in a denial of service, or
    possibly execute arbitrary code. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu
    22.04 LTS. (CVE-2022-30552, CVE-2022-30790)

    It was discovered that U-Boot incorrectly handled certain NFS lookup replies. A remote attacker could use
    this issue to cause U-Boot to crash, resulting in a denial of service, or possibly execute arbitrary code.
    This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-30767)

    Jincheng Wang discovered that U-Boot incorrectly handled certain SquashFS structures. A local attacker
    could use this issue to cause U-Boot to crash, resulting in a denial of service, or possibly execute
    arbitrary code. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS.
    (CVE-2022-33103)

    Tatsuhiko Yasumatsu discovered that U-Boot incorrectly handled certain SquashFS structures. A local
    attacker could use this issue to cause U-Boot to crash, resulting in a denial of service, or possibly
    execute arbitrary code. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS.
    (CVE-2022-33967)

    It was discovered that U-Boot incorrectly handled the i2c command. A local attacker could use this issue
    to cause U-Boot to crash, resulting in a denial of service, or possibly execute arbitrary code. This issue
    only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-34835)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5764-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34835");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-amlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-exynos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-imx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-microchip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-mvebu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-qcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-rockchip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-sifive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-sunxi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-tegra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:u-boot-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
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

var pkgs = [
    {'osver': '18.04', 'pkgname': 'u-boot', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-amlogic', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-exynos', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-imx', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-mvebu', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-qcom', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-qemu', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-rockchip', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-rpi', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-sunxi', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-tegra', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '18.04', 'pkgname': 'u-boot-tools', 'pkgver': '2020.10+dfsg-1ubuntu0~18.04.3'},
    {'osver': '20.04', 'pkgname': 'u-boot', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-amlogic', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-exynos', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-imx', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-mvebu', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-qcom', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-qemu', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-rockchip', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-rpi', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-sifive', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-sunxi', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-tegra', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '20.04', 'pkgname': 'u-boot-tools', 'pkgver': '2021.01+dfsg-3ubuntu0~20.04.5'},
    {'osver': '22.04', 'pkgname': 'u-boot', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-amlogic', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-exynos', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-imx', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-microchip', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-mvebu', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-qcom', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-qemu', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-rockchip', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-rpi', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-sifive', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-sunxi', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-tegra', 'pkgver': '2022.01+dfsg-2ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'u-boot-tools', 'pkgver': '2022.01+dfsg-2ubuntu2.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'u-boot / u-boot-amlogic / u-boot-exynos / u-boot-imx / etc');
}
