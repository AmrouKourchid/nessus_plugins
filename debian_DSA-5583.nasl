#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5583. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(187197);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_name(english:"Debian DSA-5583-1 : gst-plugins-bad1.0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5583
advisory.

    A buffer overflow was discovered in the AV1 video plugin for the GStreamer media framework, which may
    result in denial of service or potentially the execution of arbitrary code if a malformed media file is
    opened. The oldstable distribution (bullseye) is not affected. For the stable distribution (bookworm),
    this problem has been fixed in version 1.22.0-4+deb12u4. We recommend that you upgrade your gst-plugins-
    bad1.0 packages. For the detailed security status of gst-plugins-bad1.0 please refer to its security
    tracker page at: https://security-tracker.debian.org/tracker/gst-plugins-bad1.0

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/gst-plugins-bad1.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7460d4a1");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/gst-plugins-bad1.0");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5583");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gst-plugins-bad1.0 packages.

For the stable distribution (bookworm), this problem has been fixed in version 1.22.0-4+deb12u4.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-plugins-bad-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer1.0-wpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-opencv1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-bad1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-bad1.0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gst-plugins-bad-1.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'gir1.2-gst-plugins-bad-1.0', 'reference': '1.22.0-4+deb12u4'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-opencv', 'reference': '1.22.0-4+deb12u4'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-plugins-bad', 'reference': '1.22.0-4+deb12u4'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-plugins-bad-apps', 'reference': '1.22.0-4+deb12u4'},
    {'release': '12.0', 'prefix': 'gstreamer1.0-wpe', 'reference': '1.22.0-4+deb12u4'},
    {'release': '12.0', 'prefix': 'libgstreamer-opencv1.0-0', 'reference': '1.22.0-4+deb12u4'},
    {'release': '12.0', 'prefix': 'libgstreamer-plugins-bad1.0-0', 'reference': '1.22.0-4+deb12u4'},
    {'release': '12.0', 'prefix': 'libgstreamer-plugins-bad1.0-dev', 'reference': '1.22.0-4+deb12u4'}
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
