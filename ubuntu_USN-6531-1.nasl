#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6531-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186586);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-24834",
    "CVE-2022-35977",
    "CVE-2022-36021",
    "CVE-2023-25155",
    "CVE-2023-28856",
    "CVE-2023-45145"
  );
  script_xref(name:"USN", value:"6531-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM : Redis vulnerabilities (USN-6531-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6531-1 advisory.

    Seiya Nakata and Yudai Fujiwara discovered that Redis incorrectly handled certain specially crafted Lua
    scripts. An attacker could possibly use this issue to cause heap corruption and execute arbitrary code.
    (CVE-2022-24834)

    SeungHyun Lee discovered that Redis incorrectly handled specially crafted commands. An attacker could
    possibly use this issue to trigger an integer overflow, which might cause Redis to allocate impossible
    amounts of memory, resulting in a denial of service via an application crash. (CVE-2022-35977)

    Tom Levy discovered that Redis incorrectly handled crafted string matching patterns. An attacker could
    possibly use this issue to cause Redis to hang, resulting in a denial of service. (CVE-2022-36021)

    Yupeng Yang discovered that Redis incorrectly handled specially crafted commands. An attacker could
    possibly use this issue to trigger an integer overflow, resulting in a denial of service via an
    application crash. (CVE-2023-25155)

    It was discovered that Redis incorrectly handled a specially crafted command. An attacker could possibly
    use this issue to create an invalid hash field, which could potentially cause Redis to crash on future
    access. (CVE-2023-28856)

    Alexander Aleksandrovi Klimov discovered that Redis incorrectly listened to a Unix socket before setting
    proper permissions. A local attacker could possibly use this issue to connect, bypassing intended
    permissions. (CVE-2023-45145)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6531-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24834");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:redis-sentinel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:redis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:redis-tools");
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
    {'osver': '16.04', 'pkgname': 'redis-sentinel', 'pkgver': '2:3.0.6-1ubuntu0.4+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'redis-server', 'pkgver': '2:3.0.6-1ubuntu0.4+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'redis-tools', 'pkgver': '2:3.0.6-1ubuntu0.4+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'redis', 'pkgver': '5:4.0.9-1ubuntu0.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'redis-sentinel', 'pkgver': '5:4.0.9-1ubuntu0.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'redis-server', 'pkgver': '5:4.0.9-1ubuntu0.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'redis-tools', 'pkgver': '5:4.0.9-1ubuntu0.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'redis', 'pkgver': '5:5.0.7-2ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'redis-sentinel', 'pkgver': '5:5.0.7-2ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'redis-server', 'pkgver': '5:5.0.7-2ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'redis-tools', 'pkgver': '5:5.0.7-2ubuntu0.1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'redis', 'pkgver': '5:6.0.16-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'redis-sentinel', 'pkgver': '5:6.0.16-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'redis-server', 'pkgver': '5:6.0.16-1ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'redis-tools', 'pkgver': '5:6.0.16-1ubuntu1+esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redis / redis-sentinel / redis-server / redis-tools');
}
