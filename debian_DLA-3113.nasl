#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3113. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(214470);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-35530",
    "CVE-2020-35531",
    "CVE-2020-35532",
    "CVE-2020-35533"
  );

  script_name(english:"Debian dla-3113 : libraw-bin - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3113 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3113-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Helmut Grohne
    September 16, 2022                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libraw
    Version        : 0.19.2-2+deb10u1
    CVE ID         : CVE-2020-35530 CVE-2020-35531 CVE-2020-35532 CVE-2020-35533

    Multiple file parsing vulnerabilities have been fixed in libraw. They are
    concerned with the dng and x3f formats.

    CVE-2020-35530

        There is an out-of-bounds write vulnerability within the new_node()
        function (src/x3f/x3f_utils_patched.cpp) that can be triggered via a
        crafted X3F file. Reported by github user 0xfoxone.

    CVE-2020-35531

        An out-of-bounds read vulnerability exists within the
        get_huffman_diff() function (src/x3f/x3f_utils_patched.cpp) when
        reading data from an image file. Reported by github user GirlElecta.

    CVE-2020-35532

        An out-of-bounds read vulnerability exists within the
        simple_decode_row() function (src/x3f/x3f_utils_patched.cpp) which
        can be triggered via an image with a large row_stride field.
        Reported by github user GirlElecta.

    CVE-2020-35533

        An out-of-bounds read vulnerability exists within the
        LibRaw::adobe_copy_pixel() function (src/decoders/dng.cpp) when
        reading data from the image file. Reported by github user GirlElecta.

    For Debian 10 buster, these problems have been fixed in version
    0.19.2-2+deb10u1.

    We recommend that you upgrade your libraw packages.

    For the detailed security status of libraw please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libraw

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libraw");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35530");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35531");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35532");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35533");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libraw");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libraw-bin packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35533");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw19");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libraw-bin', 'reference': '0.19.2-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libraw-dev', 'reference': '0.19.2-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libraw-doc', 'reference': '0.19.2-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libraw19', 'reference': '0.19.2-2+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libraw-bin / libraw-dev / libraw-doc / libraw19');
}
