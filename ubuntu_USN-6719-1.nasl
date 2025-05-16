#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6719-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192629);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2024-28085");
  script_xref(name:"USN", value:"6719-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 : util-linux vulnerability (USN-6719-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-6719-1 advisory.

    Skyler Ferrante discovered that the util-linux wall command did not filter escape sequences from command
    line arguments. A local attacker could possibly use this issue to obtain sensitive information.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6719-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28085");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bsdextrautils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bsdutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libblkid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfdisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmount-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmartcols-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rfkill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:util-linux-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:util-linux-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uuid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uuid-runtime");
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
    {'osver': '20.04', 'pkgname': 'bsdutils', 'pkgver': '1:2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'fdisk', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libblkid-dev', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libblkid1', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libfdisk-dev', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libfdisk1', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libmount-dev', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libmount1', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libsmartcols-dev', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libsmartcols1', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'libuuid1', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'mount', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'rfkill', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'util-linux', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'util-linux-locales', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'uuid-dev', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '20.04', 'pkgname': 'uuid-runtime', 'pkgver': '2.34-0.1ubuntu9.5'},
    {'osver': '22.04', 'pkgname': 'bsdextrautils', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'bsdutils', 'pkgver': '1:2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'eject', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'fdisk', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libblkid-dev', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libblkid1', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libfdisk-dev', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libfdisk1', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libmount-dev', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libmount1', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsmartcols-dev', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libsmartcols1', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'libuuid1', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'mount', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'rfkill', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'util-linux', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'util-linux-locales', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'uuid-dev', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '22.04', 'pkgname': 'uuid-runtime', 'pkgver': '2.37.2-4ubuntu3.3'},
    {'osver': '23.10', 'pkgname': 'bsdextrautils', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'bsdutils', 'pkgver': '1:2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'eject', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'fdisk', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libblkid-dev', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libblkid1', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libfdisk-dev', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libfdisk1', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libmount-dev', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libmount1', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsmartcols-dev', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libsmartcols1', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'libuuid1', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'mount', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'rfkill', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'util-linux', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'util-linux-extra', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'util-linux-locales', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'uuid-dev', 'pkgver': '2.39.1-4ubuntu2.1'},
    {'osver': '23.10', 'pkgname': 'uuid-runtime', 'pkgver': '2.39.1-4ubuntu2.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bsdextrautils / bsdutils / eject / fdisk / libblkid-dev / libblkid1 / etc');
}
