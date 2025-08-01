#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4519-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140651);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2020-15710");
  script_xref(name:"USN", value:"4519-1");

  script_name(english:"Ubuntu 16.04 LTS : PulseAudio vulnerability (USN-4519-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-4519-1 advisory.

    Ratchanan Srirattanamet discovered that an Ubuntu-specific patch caused PulseAudio to incorrectly handle
    memory under certain error conditions in the Bluez 5 module. An attacker could use this issue to cause
    PulseAudio to crash, resulting in a denial of service, or possibly execute arbitrary code.
    (CVE-2020-15710)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4519-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15710");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-mainloop-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulsedsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-droid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-raop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-trust-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
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

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libpulse-dev', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'libpulse-mainloop-glib0', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'libpulse0', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'libpulsedsp', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-esound-compat', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-bluetooth', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-droid', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-gconf', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-jack', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-lirc', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-raop', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-trust-store', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-x11', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-module-zeroconf', 'pkgver': '1:8.0-0ubuntu3.14'},
    {'osver': '16.04', 'pkgname': 'pulseaudio-utils', 'pkgver': '1:8.0-0ubuntu3.14'}
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
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpulse-dev / libpulse-mainloop-glib0 / libpulse0 / libpulsedsp / etc');
}
