#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3926. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(209443);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2020-16156", "CVE-2023-31484");

  script_name(english:"Debian dla-3926 : libperl-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3926 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3926-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    October 21, 2024                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : perl
    Version        : 5.32.1-4+deb11u4
    CVE ID         : CVE-2020-16156 CVE-2023-31484
    Debian Bug     : 1015985 1035109

    Vulnerabilities were found in Perl's CPAN.pm, which could lead CPAN
    clients to install malicious modules.

    CVE-2020-16156

        Stig Palmquist discovered that an attacker can prepend checksums for
        modified packages to the beginning of CHECKSUMS files, before the
        cleartext PGP headers, resulting in signature verification bypass.

        CPAN.pm has been updated so that when configured to validate the
        signature on CHECKSUMS, it will refuse to install a tarball if the
        associated CHECKSUMS file isn't signed.  The gpg(1) executable is
        required in order to validate signatures.

    CVE-2023-31484

        Stig Palmquist discovered that CPAN::HTTP::Client did not verify
        X.509 certificates in the HTTP::Tiny call, which could allows an
        attacker to MITM the connection with the CPAN mirror.

        CPAN::HTTP::Client now enables the `verify_SSL` flag.  HTTPS mirrors
        therefore require a valid certificate.  The identity of the default
        mirror https://cpan.org can be verified after installing the
        'ca-certificates' package.

    For Debian 11 bullseye, these problems have been fixed in version
    5.32.1-4+deb11u4.

    We recommend that you upgrade your perl packages.

    For the detailed security status of perl please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/perl

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/perl");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-16156");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31484");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/perl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libperl-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16156");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-31484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libperl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libperl5.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-modules-5.32");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'libperl-dev', 'reference': '5.32.1-4+deb11u4'},
    {'release': '11.0', 'prefix': 'libperl5.32', 'reference': '5.32.1-4+deb11u4'},
    {'release': '11.0', 'prefix': 'perl', 'reference': '5.32.1-4+deb11u4'},
    {'release': '11.0', 'prefix': 'perl-base', 'reference': '5.32.1-4+deb11u4'},
    {'release': '11.0', 'prefix': 'perl-debug', 'reference': '5.32.1-4+deb11u4'},
    {'release': '11.0', 'prefix': 'perl-doc', 'reference': '5.32.1-4+deb11u4'},
    {'release': '11.0', 'prefix': 'perl-modules-5.32', 'reference': '5.32.1-4+deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libperl-dev / libperl5.32 / perl / perl-base / perl-debug / perl-doc / etc');
}
