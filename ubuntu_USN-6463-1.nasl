#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6463-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184088);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2023-34058", "CVE-2023-34059");
  script_xref(name:"USN", value:"6463-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : Open VM Tools vulnerabilities (USN-6463-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6463-1 advisory.

    It was discovered that Open VM Tools incorrectly handled SAML tokens. A remote attacker Guest Operations
    privileges could possibly use this issue to escalate privileges. (CVE-2023-34058)

    Matthias Gerstner discovered that Open VM Tools incorrectly handled file descriptors when dropping
    privileges. A local attacker could possibly use this issue to hijack /dev/uinput and simulate user inputs.
    (CVE-2023-34059)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6463-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools-containerinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools-salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools-sdmp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
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

var pkgs = [
    {'osver': '20.04', 'pkgname': 'open-vm-tools', 'pkgver': '2:11.3.0-2ubuntu0~ubuntu20.04.7'},
    {'osver': '20.04', 'pkgname': 'open-vm-tools-desktop', 'pkgver': '2:11.3.0-2ubuntu0~ubuntu20.04.7'},
    {'osver': '20.04', 'pkgname': 'open-vm-tools-dev', 'pkgver': '2:11.3.0-2ubuntu0~ubuntu20.04.7'},
    {'osver': '20.04', 'pkgname': 'open-vm-tools-sdmp', 'pkgver': '2:11.3.0-2ubuntu0~ubuntu20.04.7'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools', 'pkgver': '2:12.1.5-3~ubuntu0.22.04.4'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools-containerinfo', 'pkgver': '2:12.1.5-3~ubuntu0.22.04.4'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools-desktop', 'pkgver': '2:12.1.5-3~ubuntu0.22.04.4'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools-dev', 'pkgver': '2:12.1.5-3~ubuntu0.22.04.4'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools-salt-minion', 'pkgver': '2:12.1.5-3~ubuntu0.22.04.4'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools-sdmp', 'pkgver': '2:12.1.5-3~ubuntu0.22.04.4'},
    {'osver': '23.04', 'pkgname': 'open-vm-tools', 'pkgver': '2:12.1.5-3ubuntu0.23.04.3'},
    {'osver': '23.04', 'pkgname': 'open-vm-tools-containerinfo', 'pkgver': '2:12.1.5-3ubuntu0.23.04.3'},
    {'osver': '23.04', 'pkgname': 'open-vm-tools-desktop', 'pkgver': '2:12.1.5-3ubuntu0.23.04.3'},
    {'osver': '23.04', 'pkgname': 'open-vm-tools-dev', 'pkgver': '2:12.1.5-3ubuntu0.23.04.3'},
    {'osver': '23.04', 'pkgname': 'open-vm-tools-salt-minion', 'pkgver': '2:12.1.5-3ubuntu0.23.04.3'},
    {'osver': '23.04', 'pkgname': 'open-vm-tools-sdmp', 'pkgver': '2:12.1.5-3ubuntu0.23.04.3'},
    {'osver': '23.10', 'pkgname': 'open-vm-tools', 'pkgver': '2:12.3.0-1ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'open-vm-tools-containerinfo', 'pkgver': '2:12.3.0-1ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'open-vm-tools-desktop', 'pkgver': '2:12.3.0-1ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'open-vm-tools-dev', 'pkgver': '2:12.3.0-1ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'open-vm-tools-salt-minion', 'pkgver': '2:12.3.0-1ubuntu0.1'},
    {'osver': '23.10', 'pkgname': 'open-vm-tools-sdmp', 'pkgver': '2:12.3.0-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'open-vm-tools / open-vm-tools-containerinfo / open-vm-tools-desktop / etc');
}
