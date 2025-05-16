#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3305. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170983);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2018-16981",
    "CVE-2019-13217",
    "CVE-2019-13218",
    "CVE-2019-13219",
    "CVE-2019-13220",
    "CVE-2019-13221",
    "CVE-2019-13222",
    "CVE-2019-13223",
    "CVE-2021-28021",
    "CVE-2021-37789",
    "CVE-2021-42715",
    "CVE-2022-28041",
    "CVE-2022-28042"
  );

  script_name(english:"Debian dla-3305 : libstb-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3305 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3305-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/        Adrian Bunk <bunk@debian.org>
    January 31, 2023                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : libstb
    Version        : 0.0~git20180212.15.e6afb9c-1+deb10u1
    CVE ID         : CVE-2018-16981 CVE-2019-13217 CVE-2019-13218 CVE-2019-13219
                     CVE-2019-13220 CVE-2019-13221 CVE-2019-13222 CVE-2019-13223
                     CVE-2021-28021 CVE-2021-37789 CVE-2021-42715 CVE-2022-28041
                     CVE-2022-28042
    Debian Bug     : 934966 1014530 1023693 1014531 1014532

    Several vulnerabilities have been fixed in the libstb library.

    CVE-2018-16981

        Heap-based buffer overflow in stbi__out_gif_code().

    CVE-2019-13217

        Heap buffer overflow in the Vorbis start_decoder().

    CVE-2019-13218

        Division by zero in the Vorbis predict_point().

    CVE-2019-13219

        NULL pointer dereference in the Vorbis get_window().

    CVE-2019-13220

        Uninitialized stack variables in the Vorbis start_decoder().

    CVE-2019-13221

        Buffer overflow in the Vorbis compute_codewords().

    CVE-2019-13222

        Out-of-bounds read of a global buffer in the Vorbis draw_line().

    CVE-2019-13223

        Reachable assertion in the Vorbis lookup1_values().

    CVE-2021-28021

        Buffer overflow in stbi__extend_receive().

    CVE-2021-37789

        Heap-based buffer overflow in stbi__jpeg_load().

    CVE-2021-42715

        The HDR loader parsed truncated end-of-file RLE scanlines as an
        infinite sequence of zero-length runs.

    CVE-2022-28041

        Integer overflow in stbi__jpeg_decode_block_prog_dc().

    CVE-2022-28042

        Heap-based use-after-free in stbi__jpeg_huff_decode().

    For Debian 10 buster, these problems have been fixed in version
    0.0~git20180212.15.e6afb9c-1+deb10u1.

    We recommend that you upgrade your libstb packages.

    For the detailed security status of libstb please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libstb

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libstb");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13217");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13219");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13220");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13221");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13223");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28021");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37789");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42715");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28041");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28042");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libstb");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libstb-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28042");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstb0");
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
    {'release': '10.0', 'prefix': 'libstb-dev', 'reference': '0.0~git20180212.15.e6afb9c-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libstb0', 'reference': '0.0~git20180212.15.e6afb9c-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libstb-dev / libstb0');
}
