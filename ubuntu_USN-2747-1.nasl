#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2747-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86189);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2015-5950");
  script_xref(name:"USN", value:"2747-1");

  script_name(english:"Ubuntu 14.04 LTS : NVIDIA graphics drivers vulnerability (USN-2747-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-2747-1 advisory.

    Dario Weisser discovered that the NVIDIA graphics drivers incorrectly handled certain IOCTL writes. A
    local attacker could use this issue to possibly gain root privileges.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2747-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-304");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-304-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-331");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-331-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-340");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-340-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-346");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-346-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-304");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-304-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-304-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-304-updates-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-331");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-331-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-331-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-331-updates-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-331-updates-uvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-331-uvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340-updates-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340-updates-uvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340-uvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346-updates-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346-updates-uvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346-uvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-current");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-current-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-current-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-current-updates-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-experimental-304");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-experimental-304-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-304");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-304-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-331");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-331-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-340");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-340-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-346");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-346-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-304");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-304-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-331");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-331-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-340");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-340-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-346");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-346-updates");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libcuda1-304', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'libcuda1-304-updates', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'libcuda1-331', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'libcuda1-331-updates', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'libcuda1-340', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'libcuda1-340-updates', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'libcuda1-346', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'libcuda1-346-updates', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-304', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-304-dev', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-304-updates', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-304-updates-dev', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-331', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-331-dev', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-331-updates', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-331-updates-dev', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-331-updates-uvm', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-331-uvm', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-340', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-340-dev', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-340-updates', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-340-updates-dev', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-340-updates-uvm', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-340-uvm', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-346', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-346-dev', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-346-updates', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-346-updates-dev', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-346-updates-uvm', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-346-uvm', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-current', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-current-dev', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-current-updates', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-current-updates-dev', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-experimental-304', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-experimental-304-dev', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-libopencl1-304', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-libopencl1-304-updates', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-libopencl1-331', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-libopencl1-331-updates', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-libopencl1-340', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-libopencl1-340-updates', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-libopencl1-346', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-libopencl1-346-updates', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-opencl-icd-304', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-opencl-icd-304-updates', 'pkgver': '304.128-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-opencl-icd-331', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-opencl-icd-331-updates', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-opencl-icd-340', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-opencl-icd-340-updates', 'pkgver': '340.93-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-opencl-icd-346', 'pkgver': '346.96-0ubuntu0.0.1'},
    {'osver': '14.04', 'pkgname': 'nvidia-opencl-icd-346-updates', 'pkgver': '346.96-0ubuntu0.0.1'}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcuda1-304 / libcuda1-304-updates / libcuda1-331 / etc');
}
