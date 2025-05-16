#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4073. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216945);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id("CVE-2025-0518", "CVE-2025-22919", "CVE-2025-22921");
  script_xref(name:"IAVB", value:"2025-B-0018-S");

  script_name(english:"Debian dla-4073 : ffmpeg - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4073 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4073-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                    Thorsten Alteholz
    March 01, 2025                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : ffmpeg
    Version        : 7:4.3.8-0+deb11u3
    CVE ID         : CVE-2025-0518 CVE-2025-22919 CVE-2025-22921


    Several issues have been found in ffmpeg, a package of tools for
    transcoding, streaming and playing of multimedia files.
    The issues are related to out-of-bounds read, assert errors and NULL
    pointer dereferences.


    For Debian 11 bullseye, these problems have been fixed in version
    7:4.3.8-0+deb11u3.

    We recommend that you upgrade your ffmpeg packages.

    For the detailed security status of ffmpeg please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/ffmpeg

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ffmpeg");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-0518");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-22919");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-22921");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ffmpeg");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ffmpeg packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0518");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-22921");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ffmpeg', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'ffmpeg-doc', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavcodec-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavcodec-extra', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavcodec-extra58', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavcodec58', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavdevice-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavdevice58', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavfilter-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavfilter-extra', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavfilter-extra7', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavfilter7', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavformat-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavformat58', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavresample-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavresample4', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavutil-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libavutil56', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libpostproc-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libpostproc55', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libswresample-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libswresample3', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libswscale-dev', 'reference': '7:4.3.8-0+deb11u3'},
    {'release': '11.0', 'prefix': 'libswscale5', 'reference': '7:4.3.8-0+deb11u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / ffmpeg-doc / libavcodec-dev / libavcodec-extra / etc');
}
