#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2728. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152193);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2021-25801",
    "CVE-2021-25802",
    "CVE-2021-25803",
    "CVE-2021-25804"
  );

  script_name(english:"Debian DLA-2728-1 : vlc - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2728 advisory.

    It was discovered that there were a number of issues in VideoLAN (aka 'vlc', a popular video and
    multimedia player: CVE-2021-25801 A buffer overflow vulnerability in the __Parse_indx component allowed
    attackers to cause an out-of-bounds read via a crafted .avi file. CVE-2021-25802 A buffer overflow
    vulnerability in the AVI_ExtractSubtitle component could have allowed attackers to cause an out-of-bounds
    read via a crafted .avi file. CVE-2021-25803 A buffer overflow vulnerability in the
    vlc_input_attachment_New component allowed attackers to cause an out-of-bounds read via a specially-
    crafted .avi file. CVE-2021-25804 A NULL-pointer dereference in Open in avi.c can result in a denial of
    service (DoS) vulnerability. For Debian 9 Stretch, these problems have been fixed in version
    3.0.11-0+deb9u2. We recommend that you upgrade your vlc packages. Further information about Debian LTS
    security advisories, how to apply these updates to your system and frequently asked questions can be found
    at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2728");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25801");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25803");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25804");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/vlc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vlc packages.

For Debian 9 Stretch, these problems have been fixed in version 3.0.11-0+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlccore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlccore8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvlccore9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-access-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-skins2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-video-output");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-video-splitter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-visualization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc-plugin-zvbi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libvlc-bin', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'libvlc-dev', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'libvlc5', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'libvlccore-dev', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'libvlccore8', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'libvlccore9', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-bin', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-data', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-l10n', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-nox', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-access-extra', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-base', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-fluidsynth', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-jack', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-notify', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-qt', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-samba', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-sdl', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-skins2', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-svg', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-video-output', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-video-splitter', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-visualization', 'reference': '3.0.11-0+deb9u2'},
    {'release': '9.0', 'prefix': 'vlc-plugin-zvbi', 'reference': '3.0.11-0+deb9u2'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvlc-bin / libvlc-dev / libvlc5 / libvlccore-dev / libvlccore8 / etc');
}
