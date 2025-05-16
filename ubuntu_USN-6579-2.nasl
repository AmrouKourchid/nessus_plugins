#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6579-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188073);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2018-1311");
  script_xref(name:"USN", value:"6579-2");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 ESM / 23.04 / 23.10 : Xerces-C++ vulnerability (USN-6579-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 ESM / 23.04 / 23.10 host has packages installed that are affected by a vulnerability
as referenced in the USN-6579-2 advisory.

    USN-6579-1 fixed a vulnerability in Xerces-C++. This update provides the corresponding update for Ubuntu
    20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 23.04 and Ubuntu 23.10.



Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6579-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxerces-c-dev, libxerces-c-samples and / or libxerces-c3.2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1311");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxerces-c-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxerces-c-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxerces-c3.2");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libxerces-c-dev', 'pkgver': '3.2.2+debian-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libxerces-c-samples', 'pkgver': '3.2.2+debian-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libxerces-c3.2', 'pkgver': '3.2.2+debian-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libxerces-c-dev', 'pkgver': '3.2.3+debian-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libxerces-c-samples', 'pkgver': '3.2.3+debian-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libxerces-c3.2', 'pkgver': '3.2.3+debian-3ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '23.04', 'pkgname': 'libxerces-c-dev', 'pkgver': '3.2.4+debian-1ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libxerces-c-samples', 'pkgver': '3.2.4+debian-1ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'libxerces-c3.2', 'pkgver': '3.2.4+debian-1ubuntu0.23.04.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libxerces-c-dev', 'pkgver': '3.2.4+debian-1ubuntu0.23.10.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libxerces-c-samples', 'pkgver': '3.2.4+debian-1ubuntu0.23.10.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libxerces-c3.2', 'pkgver': '3.2.4+debian-1ubuntu0.23.10.1', 'ubuntu_pro': FALSE}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxerces-c-dev / libxerces-c-samples / libxerces-c3.2');
}
