#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5608. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(189723);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-0444");

  script_name(english:"Debian dsa-5608 : gir1.2-gst-plugins-bad-1.0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5608
advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5608-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    January 27, 2024                      https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : gst-plugins-bad1.0
    CVE ID         : CVE-2024-0444

    A heap-based buffer overflow during tile list parsing was discovered in
    the AV1 video codec parser for the GStreamer media framework, which may
    result in denial of service or potentially the execution of arbitrary
    code if a malformed media file is opened.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 1.18.4-3+deb11u4.

    For the stable distribution (bookworm), this problem has been fixed in
    version 1.22.0-4+deb12u5.

    We recommend that you upgrade your gst-plugins-bad1.0 packages.

    For the detailed security status of gst-plugins-bad1.0 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/gst-plugins-bad1.0

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQKTBAEBCgB9FiEERkRAmAjBceBVMd3uBUy48xNDz0QFAmW1XvtfFIAAAAAALgAo
    aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDQ2
    NDQ0MDk4MDhDMTcxRTA1NTMxRERFRTA1NENCOEYzMTM0M0NGNDQACgkQBUy48xND
    z0T6lQ//U5/FcuUV+SLF3IYzbSGP3nxOl3njQNMQz12woGd8SJdFpsEgeyOFUqwE
    1u6xUjNbryI3N/U3zGxEH3P5gZdcxXbQX3dWqHr6IrBC1ciBwKZrtmcmy9ME2OZd
    1r2QYGNxGYr2d/E9IV6lvT6L2MPeKTbEmAUjCGgY/nsPi9P2ECwufD7KEHh+6IXn
    5WRPEFIWioOXWhiBn02x612VHJUvux5geBz6oLkl9sc2V9coHx19kywaC9W2JMtt
    SlyBaw3s7l2lv25rwTYCie1YmAgjsvnyZu3ijGMwHp/Sa7RYUkTC09S/fzuZlFOA
    Dz5HRslsjvlk0SomPg5A0J6eDYVQUqE3fq3A2zRtkDbeGbScAmc4eyR1d4LE0FqT
    POUxZoCR84fP542vOqLimvfdnkkaPSJwcQJRrwKx4r/hYFwOi4W1gwy90at7MQlj
    zwrfExMcXu9B3WmzmwAcTsX9nrgyiXNKH3Lib0gT+93TbqdhUNHuj9zC885JfOwx
    Th+jRaas4dyx4Tjaz83pJaUzEEIgAHByfr5N1UltvIUmO7AX9C9iLLyVVmgb2Qz0
    ujdc1N8XSqcvB52psJe5o6oEx6UbAVTH48PGrCuYY2kfzKKHYUan6n8MILRw8Is4
    FaUz4BAUd6Fjgo+jG/oS32grK7aujTbqRCiDaTDLcT/vywZldQA=
    =giTa
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/gst-plugins-bad1.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7460d4a1");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0444");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/gst-plugins-bad1.0");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/gst-plugins-bad1.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-gst-plugins-bad-1.0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gst-plugins-bad-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-bad-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-wpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-opencv1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-bad1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-bad1.0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gir1.2-gst-plugins-bad-1.0', 'reference': '1.18.4-3+deb11u4'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-opencv', 'reference': '1.18.4-3+deb11u4'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-plugins-bad', 'reference': '1.18.4-3+deb11u4'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-plugins-bad-apps', 'reference': '1.18.4-3+deb11u4'},
    {'release': '11.0', 'prefix': 'gstreamer1.0-wpe', 'reference': '1.18.4-3+deb11u4'},
    {'release': '11.0', 'prefix': 'libgstreamer-opencv1.0-0', 'reference': '1.18.4-3+deb11u4'},
    {'release': '11.0', 'prefix': 'libgstreamer-plugins-bad1.0-0', 'reference': '1.18.4-3+deb11u4'},
    {'release': '11.0', 'prefix': 'libgstreamer-plugins-bad1.0-dev', 'reference': '1.18.4-3+deb11u4'},
    {'release': '12.0', 'prefix': 'gir1.2-gst-plugins-bad-1.0', 'reference': '1.22.0-4+deb12u5'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-opencv', 'reference': '1.22.0-4+deb12u5'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-plugins-bad', 'reference': '1.22.0-4+deb12u5'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-plugins-bad-apps', 'reference': '1.22.0-4+deb12u5'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-wpe', 'reference': '1.22.0-4+deb12u5'},
    {'release': '12.0', 'prefix': 'libgstreamer-opencv1.0-0', 'reference': '1.22.0-4+deb12u5'},
    {'release': '12.0', 'prefix': 'libgstreamer-plugins-bad1.0-0', 'reference': '1.22.0-4+deb12u5'},
    {'release': '12.0', 'prefix': 'libgstreamer-plugins-bad1.0-dev', 'reference': '1.22.0-4+deb12u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-gst-plugins-bad-1.0 / gstreamer1.0-opencv / etc');
}
