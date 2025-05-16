#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3278. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170240);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-1354",
    "CVE-2022-1355",
    "CVE-2022-2056",
    "CVE-2022-2057",
    "CVE-2022-2058",
    "CVE-2022-2867",
    "CVE-2022-2868",
    "CVE-2022-2869",
    "CVE-2022-3570",
    "CVE-2022-3597",
    "CVE-2022-3598",
    "CVE-2022-3599",
    "CVE-2022-3626",
    "CVE-2022-3627",
    "CVE-2022-3970",
    "CVE-2022-34526"
  );

  script_name(english:"Debian dla-3278 : libtiff-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3278 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3278-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Sylvain Beucler
    January 20, 2023                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : tiff
    Version        : 4.1.0+git191117-2~deb10u5
    CVE ID         : CVE-2022-1354 CVE-2022-1355 CVE-2022-2056 CVE-2022-2057
                     CVE-2022-2058 CVE-2022-2867 CVE-2022-2868 CVE-2022-2869
                     CVE-2022-3570 CVE-2022-3597 CVE-2022-3598 CVE-2022-3599
                     CVE-2022-3626 CVE-2022-3627 CVE-2022-3970 CVE-2022-34526
    Debian Bug     : 1011160 1014494 1022555 1024737

    Multiple vulnerabilities were found in tiff, a library and tools
    providing support for the Tag Image File Format (TIFF), leading to
    denial of service (DoS) and possibly local code execution.

    CVE-2022-1354

        A heap buffer overflow flaw was found in Libtiffs' tiffinfo.c in
        TIFFReadRawDataStriped() function. This flaw allows an attacker to
        pass a crafted TIFF file to the tiffinfo tool, triggering a heap
        buffer overflow issue and causing a crash that leads to a denial
        of service.

    CVE-2022-1355

        A stack buffer overflow flaw was found in Libtiffs' tiffcp.c in
        main() function. This flaw allows an attacker to pass a crafted
        TIFF file to the tiffcp tool, triggering a stack buffer overflow
        issue, possibly corrupting the memory, and causing a crash that
        leads to a denial of service.

    CVE-2022-2056, CVE-2022-2057, CVE-2022-2058

        Divide By Zero error in tiffcrop allows attackers to cause a
        denial-of-service via a crafted tiff file.

    CVE-2022-2867, CVE-2022-2868, CVE-2022-2869

        libtiff's tiffcrop utility has underflow and input validation flaw
        that can lead to out of bounds read and write. An attacker who
        supplies a crafted file to tiffcrop (likely via tricking a user to
        run tiffcrop on it with certain parameters) could cause a crash or
        in some cases, further exploitation.

    CVE-2022-3570, CVE-2022-3598

        Multiple heap buffer overflows in tiffcrop.c utility in libtiff
        allows attacker to trigger unsafe or out of bounds memory access
        via crafted TIFF image file which could result into application
        crash, potential information disclosure or any other
        context-dependent impact.

    CVE-2022-3597, CVE-2022-3626, CVE-2022-3627

        Out-of-bounds write, allowing attackers to cause a
        denial-of-service via a crafted tiff file.

    CVE-2022-3599

        Out-of-bounds read in writeSingleSection in tools/tiffcrop.c,
        allowing attackers to cause a denial-of-service via a crafted tiff
        file.

    CVE-2022-3970

        Affects the function TIFFReadRGBATileExt of the file
        libtiff/tif_getimage.c. The manipulation leads to integer
        overflow.

    CVE-2022-34526

        A stack overflow was discovered in the _TIFFVGetField function of
        Tiffsplit. This vulnerability allows attackers to cause a Denial
        of Service (DoS) via a crafted TIFF file parsed by the tiffsplit
        or tiffcrop utilities.

    For Debian 10 buster, these problems have been fixed in version
    4.1.0+git191117-2~deb10u5.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1354");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1355");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2056");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2057");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2867");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2868");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2869");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34526");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3570");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3626");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3970");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/tiff");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libtiff-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2058");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3970");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/21");

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
    {'release': '10.0', 'prefix': 'libtiff-dev', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff-doc', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff-opengl', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff-tools', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff5', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff5-dev', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiffxx5', 'reference': '4.1.0+git191117-2~deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff-dev / libtiff-doc / libtiff-opengl / libtiff-tools / libtiff5 / etc');
}
