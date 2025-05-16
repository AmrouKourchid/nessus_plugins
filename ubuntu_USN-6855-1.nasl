#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6855-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201111);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2024-36600");
  script_xref(name:"USN", value:"6855-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS : libcdio vulnerability (USN-6855-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS host has packages
installed that are affected by a vulnerability as referenced in the USN-6855-1 advisory.

    Mansour Gashasbi discovered that libcdio incorrectly handled certain memory operations when parsing an ISO
    file, leading to a buffer overflow vulnerability. An attacker could use this to cause a denial of service

    or possibly execute arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6855-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36600");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio++1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio++1t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-cdda-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-cdda1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-paranoia-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-paranoia1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio19t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660++0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660++0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660-11t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libudf0t64");
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
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04 / 22.04 / 23.10 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libcdio-cdda-dev', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libcdio-cdda1', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libcdio-dev', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libcdio-paranoia-dev', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libcdio-paranoia1', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libcdio-utils', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libcdio13', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libiso9660-8', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libiso9660-dev', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libudf-dev', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libudf0', 'pkgver': '0.83-4.1ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcdio-cdda-dev', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcdio-cdda1', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcdio-dev', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcdio-paranoia-dev', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcdio-paranoia1', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcdio-utils', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcdio13', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libiso9660-8', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libiso9660-dev', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libudf-dev', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libudf0', 'pkgver': '0.83-4.2ubuntu1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libcdio-dev', 'pkgver': '1.0.0-2ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libcdio-utils', 'pkgver': '1.0.0-2ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libcdio17', 'pkgver': '1.0.0-2ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libiso9660-10', 'pkgver': '1.0.0-2ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libiso9660-dev', 'pkgver': '1.0.0-2ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libudf-dev', 'pkgver': '1.0.0-2ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libudf0', 'pkgver': '1.0.0-2ubuntu2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libcdio-dev', 'pkgver': '2.0.0-2ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libcdio-utils', 'pkgver': '2.0.0-2ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libcdio18', 'pkgver': '2.0.0-2ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libiso9660-11', 'pkgver': '2.0.0-2ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libiso9660-dev', 'pkgver': '2.0.0-2ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libudf-dev', 'pkgver': '2.0.0-2ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libudf0', 'pkgver': '2.0.0-2ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcdio++-dev', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcdio++1', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcdio-dev', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcdio-utils', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcdio19', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libiso9660++-dev', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libiso9660++0', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libiso9660-11', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libiso9660-dev', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libudf-dev', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libudf0', 'pkgver': '2.1.0-3ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcdio++-dev', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcdio++1', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcdio-dev', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcdio-utils', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcdio19', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libiso9660++-dev', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libiso9660++0', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libiso9660-11', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libiso9660-dev', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libudf-dev', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libudf0', 'pkgver': '2.1.0-4ubuntu0.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libcdio++-dev', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libcdio++1t64', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libcdio-dev', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libcdio-utils', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libcdio19t64', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libiso9660++-dev', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libiso9660++0t64', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libiso9660-11t64', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libiso9660-dev', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libudf-dev', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libudf0t64', 'pkgver': '2.1.0-4.1ubuntu1.2', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcdio++-dev / libcdio++1 / libcdio++1t64 / libcdio-cdda-dev / etc');
}
