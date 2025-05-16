#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4336-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151919);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id(
    "CVE-2016-2226",
    "CVE-2016-4487",
    "CVE-2016-4488",
    "CVE-2016-4489",
    "CVE-2016-4490",
    "CVE-2016-4491",
    "CVE-2016-4492",
    "CVE-2016-4493",
    "CVE-2016-6131",
    "CVE-2017-6965",
    "CVE-2017-6966",
    "CVE-2017-6969",
    "CVE-2017-7209",
    "CVE-2017-7210",
    "CVE-2017-7223",
    "CVE-2017-7224",
    "CVE-2017-7225",
    "CVE-2017-7226",
    "CVE-2017-7227",
    "CVE-2017-7299",
    "CVE-2017-7300",
    "CVE-2017-7301",
    "CVE-2017-7302",
    "CVE-2017-7614",
    "CVE-2017-8393",
    "CVE-2017-8394",
    "CVE-2017-8395",
    "CVE-2017-8396",
    "CVE-2017-8397",
    "CVE-2017-8398",
    "CVE-2017-8421",
    "CVE-2017-9038",
    "CVE-2017-9039",
    "CVE-2017-9040",
    "CVE-2017-9041",
    "CVE-2017-9042",
    "CVE-2017-9044",
    "CVE-2017-9742",
    "CVE-2017-9744",
    "CVE-2017-9745",
    "CVE-2017-9746",
    "CVE-2017-9747",
    "CVE-2017-9748",
    "CVE-2017-9749",
    "CVE-2017-9750",
    "CVE-2017-9751",
    "CVE-2017-9752",
    "CVE-2017-9753",
    "CVE-2017-9754",
    "CVE-2017-9755",
    "CVE-2017-9756",
    "CVE-2017-9954",
    "CVE-2017-12448",
    "CVE-2017-12449",
    "CVE-2017-12450",
    "CVE-2017-12451",
    "CVE-2017-12452",
    "CVE-2017-12453",
    "CVE-2017-12454",
    "CVE-2017-12455",
    "CVE-2017-12456",
    "CVE-2017-12457",
    "CVE-2017-12458",
    "CVE-2017-12459",
    "CVE-2017-12799",
    "CVE-2017-12967",
    "CVE-2017-13710",
    "CVE-2017-14128",
    "CVE-2017-14129",
    "CVE-2017-14130",
    "CVE-2017-14333",
    "CVE-2017-14529",
    "CVE-2017-14930",
    "CVE-2017-14932",
    "CVE-2017-14938",
    "CVE-2017-14939",
    "CVE-2017-14940",
    "CVE-2017-15020",
    "CVE-2017-15021",
    "CVE-2017-15022",
    "CVE-2017-15024",
    "CVE-2017-15025",
    "CVE-2017-15225",
    "CVE-2017-15938",
    "CVE-2017-15939",
    "CVE-2017-15996",
    "CVE-2017-16826",
    "CVE-2017-16827",
    "CVE-2017-16828",
    "CVE-2017-16831",
    "CVE-2017-16832",
    "CVE-2017-17080",
    "CVE-2017-17121",
    "CVE-2017-17123",
    "CVE-2017-17124",
    "CVE-2017-17125",
    "CVE-2018-6323",
    "CVE-2018-6543",
    "CVE-2018-6759",
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945",
    "CVE-2018-9138",
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535",
    "CVE-2018-12641",
    "CVE-2018-12697",
    "CVE-2018-12698",
    "CVE-2018-12699",
    "CVE-2018-12934",
    "CVE-2018-13033",
    "CVE-2018-17358",
    "CVE-2018-17359",
    "CVE-2018-17360",
    "CVE-2018-17794",
    "CVE-2018-17985",
    "CVE-2018-18309",
    "CVE-2018-18483",
    "CVE-2018-18484",
    "CVE-2018-18605",
    "CVE-2018-18606",
    "CVE-2018-18607",
    "CVE-2018-18700",
    "CVE-2018-18701",
    "CVE-2018-19931",
    "CVE-2018-19932",
    "CVE-2018-20002",
    "CVE-2018-20623",
    "CVE-2018-20671",
    "CVE-2018-1000876",
    "CVE-2019-9070",
    "CVE-2019-9071",
    "CVE-2019-9073",
    "CVE-2019-9074",
    "CVE-2019-9075",
    "CVE-2019-9077",
    "CVE-2019-12972",
    "CVE-2019-14250",
    "CVE-2019-14444",
    "CVE-2019-17450",
    "CVE-2019-17451"
  );
  script_xref(name:"USN", value:"4336-2");

  script_name(english:"Ubuntu 16.04 ESM : GNU binutils vulnerabilities (USN-4336-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4336-2 advisory.

    USN-4336-1 fixed several vulnerabilities in GNU binutils. This update provides the corresponding update
    for Ubuntu 16.04 ESM.



Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4336-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12699");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-aarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-alpha-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabihf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-hppa-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-m68k-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64el-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsel-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-s390x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-sh4-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-source");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'binutils', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-dev', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-mips-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-mips64-linux-gnuabi64', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-mips64el-linux-gnuabi64', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-mipsel-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'binutils-source', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-aarch64-linux-gnu / binutils-alpha-linux-gnu / etc');
}
