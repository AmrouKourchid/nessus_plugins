#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3504. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(178842);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-37328");

  script_name(english:"Debian dla-3504 : gir1.2-gst-plugins-base-1.0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3504
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3504-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                    Thorsten Alteholz
    July 25, 2023                                 https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : gst-plugins-base1.0
    Version        : 1.14.4-2+deb10u2
    CVE ID         : CVE-2023-37328


    Multiple multiple vulnerabilities were discovered in plugins for the
    GStreamer media framework and its codecs and demuxers, which may result in
    denial of service or potentially the execution of arbitrary code if a
    malformed media file is opened.



    For Debian 10 buster, this problem has been fixed in version
    1.14.4-2+deb10u2.

    We recommend that you upgrade your gst-plugins-base1.0 packages.

    For the detailed security status of gst-plugins-base1.0 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/gst-plugins-base1.0

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/gst-plugins-base1.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43b9aaa1");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37328");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/gst-plugins-base1.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-gst-plugins-base-1.0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-37328");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gst-plugins-base-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-base-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-base-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-base-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-gl1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-base1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-base1.0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'gir1.2-gst-plugins-base-1.0', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'gstreamer1.0-alsa', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'gstreamer1.0-gl', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'gstreamer1.0-plugins-base', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'gstreamer1.0-plugins-base-apps', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'gstreamer1.0-plugins-base-dbg', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'gstreamer1.0-plugins-base-doc', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'gstreamer1.0-x', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libgstreamer-gl1.0-0', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libgstreamer-plugins-base1.0-0', 'reference': '1.14.4-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libgstreamer-plugins-base1.0-dev', 'reference': '1.14.4-2+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-gst-plugins-base-1.0 / gstreamer1.0-alsa / gstreamer1.0-gl / etc');
}
