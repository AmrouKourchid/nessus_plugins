#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3429. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176199);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2021-20176",
    "CVE-2021-20241",
    "CVE-2021-20243",
    "CVE-2021-20244",
    "CVE-2021-20245",
    "CVE-2021-20246",
    "CVE-2021-20309",
    "CVE-2021-20312",
    "CVE-2021-20313",
    "CVE-2021-39212",
    "CVE-2022-28463",
    "CVE-2022-32545",
    "CVE-2022-32546",
    "CVE-2022-32547"
  );
  script_xref(name:"IAVB", value:"2021-B-0017-S");
  script_xref(name:"IAVB", value:"2022-B-0032-S");
  script_xref(name:"IAVB", value:"2022-B-0019-S");

  script_name(english:"Debian dla-3429 : imagemagick - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3429 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3429-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                    Bastien Roucaries
    May 21, 2023                                  https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : imagemagick
    Version        : 8:6.9.10.23+dfsg-2.1+deb10u5
    CVE ID         : CVE-2021-20176 CVE-2021-20241 CVE-2021-20243 CVE-2021-20244
                     CVE-2021-20245 CVE-2021-20246 CVE-2021-20309 CVE-2021-20312
                     CVE-2021-20313 CVE-2021-39212 CVE-2022-28463 CVE-2022-32545
                     CVE-2022-32546 CVE-2022-32547
    Debian Bug     : 996588 1013282 1016442

    Multiple vulnerabilities were fixed in imagemagick, a software suite,
    used for editing and manipulating digital images.

    CVE-2021-20176

        A divide by zero was found in gem.c file.

    CVE-2021-20241

        A divide by zero was found in  jp2 coder.

    CVE-2021-20243

        A divide by zero was found in dcm coder.

    CVE-2021-20244

        A divide by zero was found in fx.c.

    CVE-2021-20245

        A divide by zero was found in webp coder.

    CVE-2021-20246

        A divide by zero was found in resample.c.

    CVE-2021-20309

        A divide by zero was found in WaveImage.c

    CVE-2021-20312

        An integer overflow was found in WriteTHUMBNAILImage()
        of coders/thumbnail.c

    CVE-2021-20313

        A potential cipher leak was found when the calculate
        signatures in TransformSignature().

    CVE-2021-39212

        A policy bypass was found for postscript files.

    CVE-2022-28463

        A bufer overflow was found in  buffer overflow in cin coder.

    CVE-2022-32545

        A undefined behavior (conversion outside the range of
        representable values of type 'unsigned char') was found in psd
        file handling.

    CVE-2022-32546

        A undefined behavior (conversion outside the range of
        representable values of type 'long') was found in pcl
        file handling.

    CVE-2022-32547

        An unaligned access was found in property.c

    For Debian 10 buster, these problems have been fixed in version
    8:6.9.10.23+dfsg-2.1+deb10u5.

    We recommend that you upgrade your imagemagick packages.

    For the detailed security status of imagemagick please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/imagemagick

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/imagemagick");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20176");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20241");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20245");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20246");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20309");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20312");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20313");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39212");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28463");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32546");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32547");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/imagemagick");
  script_set_attribute(attribute:"solution", value:
"Upgrade the imagemagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'imagemagick', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-6-common', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-6-doc', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-6.q16', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-6.q16hdri', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-common', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-doc', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libimage-magick-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libimage-magick-q16-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libimage-magick-q16hdri-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16-8', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16hdri-8', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6-arch-config', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-6-extra', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-6-extra', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16hdri-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'perlmagick', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6-doc / etc');
}
