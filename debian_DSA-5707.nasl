#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5707. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(200367);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_name(english:"Debian dsa-5707 : libvlc-bin - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5707
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5707-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    June 11, 2024                         https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : vlc
    CVE ID         : not yet available

    A buffer overflow was discovered in the MMS module of the VLC media
    player.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 3.0.21-0+deb11u1.

    For the stable distribution (bookworm), this problem has been fixed in
    version 3.0.21-0+deb12u1.

    We recommend that you upgrade your vlc packages.

    For the detailed security status of vlc please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/vlc

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/vlc");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/vlc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libvlc-bin packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlccore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlccore9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-access-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-skins2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-video-output");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-video-splitter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-visualization");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'libvlc-bin', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libvlc-dev', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libvlc5', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libvlccore-dev', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libvlccore9', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-bin', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-data', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-l10n', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-access-extra', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-base', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-fluidsynth', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-jack', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-notify', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-qt', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-samba', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-skins2', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-svg', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-video-output', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-video-splitter', 'reference': '3.0.21-0+deb12u1'},
    {'release': '12.0', 'prefix': 'vlc-plugin-visualization', 'reference': '3.0.21-0+deb12u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvlc-bin / libvlc-dev / libvlc5 / libvlccore-dev / libvlccore9 / vlc / etc');
}
