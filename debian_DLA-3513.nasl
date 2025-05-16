#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3513. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(179135);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2023-2908",
    "CVE-2023-3316",
    "CVE-2023-3618",
    "CVE-2023-25433",
    "CVE-2023-26965",
    "CVE-2023-26966",
    "CVE-2023-38288",
    "CVE-2023-38289"
  );

  script_name(english:"Debian dla-3513 : libtiff-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3513 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3513-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    July 31, 2023                                 https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : tiff
    Version        : 4.1.0+git191117-2~deb10u8
    CVE ID         : CVE-2023-2908 CVE-2023-3316 CVE-2023-3618 CVE-2023-25433
                     CVE-2023-26965 CVE-2023-26966 CVE-2023-38288 CVE-2023-38289
    Debian Bug     : 1040945

    Multiple vulnerabilities were found in tiff, a library and tools
    providing support for the Tag Image File Format (TIFF).


    CVE-2023-2908

        NULL pointer dereference in tif_dir.c

    CVE-2023-3316

        NULL pointer dereference in TIFFClose()

    CVE-2023-3618

        Buffer overflow in tiffcrop

    CVE-2023-25433

        Buffer overflow in tiffcrop

    CVE-2023-26965

        Use after free in tiffcrop

    CVE-2023-26966

        Buffer overflow in uv_encode()

    CVE-2023-38288

        Integer overflow in tiffcp

    CVE-2023-38289

        Integer overflow in raw2tiff

    For Debian 10 buster, these problems have been fixed in version
    4.1.0+git191117-2~deb10u8.

    We recommend that you upgrade your tiff packages.

    For the detailed security status of tiff please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/tiff

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tiff");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-25433");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-26965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-26966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2908");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3316");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3618");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38288");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38289");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/tiff");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libtiff-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3618");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
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
    {'release': '10.0', 'prefix': 'libtiff-dev', 'reference': '4.1.0+git191117-2~deb10u8'},
    {'release': '10.0', 'prefix': 'libtiff-doc', 'reference': '4.1.0+git191117-2~deb10u8'},
    {'release': '10.0', 'prefix': 'libtiff-opengl', 'reference': '4.1.0+git191117-2~deb10u8'},
    {'release': '10.0', 'prefix': 'libtiff-tools', 'reference': '4.1.0+git191117-2~deb10u8'},
    {'release': '10.0', 'prefix': 'libtiff5', 'reference': '4.1.0+git191117-2~deb10u8'},
    {'release': '10.0', 'prefix': 'libtiff5-dev', 'reference': '4.1.0+git191117-2~deb10u8'},
    {'release': '10.0', 'prefix': 'libtiffxx5', 'reference': '4.1.0+git191117-2~deb10u8'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff-dev / libtiff-doc / libtiff-opengl / libtiff-tools / libtiff5 / etc');
}
