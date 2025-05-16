#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4142. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(234954);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2025-43961",
    "CVE-2025-43962",
    "CVE-2025-43963",
    "CVE-2025-43964"
  );
  script_xref(name:"IAVA", value:"2025-A-0306");

  script_name(english:"Debian dla-4142 : libraw-bin - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4142 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4142-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Andreas Henriksson
    April 29, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libraw
    Version        : 0.20.2-1+deb11u2
    CVE ID         : CVE-2025-43961 CVE-2025-43962 CVE-2025-43963 CVE-2025-43964
    Debian Bug     : 1103781 1103782 1103783

    LibRaw is a library for reading RAW files obtained from digital photo cameras
    (CRW/CR2, NEF, RAF, DNG, and others).

    CVE-2025-43961

        metadata/tiff.cpp has an out-of-bounds read in the Fujifilm 0xf00c tag
        parser.

    CVE-2025-43962

        phase_one_correct in decoders/load_mfbacks.cpp has out-of-bounds reads for
        tag 0x412 processing, related to large w0 or w1 values or the frac and mult
        calculations.

    CVE-2025-43963

        phase_one_correct in decoders/load_mfbacks.cpp allows out-of-buffer access
        because split_col and split_row values are not checked in 0x041f tag
        processing.

    CVE-2025-43964

        tag 0x412 processing in phase_one_correct in decoders/load_mfbacks.cpp does
        not enforce minimum w0 and w1 values.

    For Debian 11 bullseye, these problems have been fixed in version
    0.20.2-1+deb11u2.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-43961");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-43962");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-43963");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-43964");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libraw");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libraw-bin packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-43964");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libraw20");
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
    {'release': '11.0', 'prefix': 'libraw-bin', 'reference': '0.20.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libraw-dev', 'reference': '0.20.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libraw-doc', 'reference': '0.20.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libraw20', 'reference': '0.20.2-1+deb11u2'}
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
    severity   : SECURITY_NOTE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libraw-bin / libraw-dev / libraw-doc / libraw20');
}
