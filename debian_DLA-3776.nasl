#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3776. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192597);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-30590", "CVE-2023-46809", "CVE-2024-22025");

  script_name(english:"Debian dla-3776 : libnode-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3776 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3776-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    March 26, 2024                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : nodejs
    Version        : 10.24.0~dfsg-1~deb10u4
    CVE ID         : CVE-2023-30590 CVE-2023-46809 CVE-2024-22025
    Debian Bug     : 1039990 1064055

    Vulnerabilities have been found in Node.js, which could lead to denial
    of service or information disclosure.

    CVE-2023-30590

        Ben Smyth reported an inconsistency between implementation and
        documented design of the The generateKeys() API function, which
        only generates missing (or outdated) keys, that is, it only
        generates a private key if none has been set yet.
        The documented behavior has been updated to reflect the current
        implementation.

    CVE-2023-46809

        It was discovered that Node.js was vulnerable to the Marvin Attack,
        allowing a covert timing side-channel during PKCS#1 v1.5 padding
        error handling.  An attacker could remotely exploit the
        vulnerability to decrypt captured RSA ciphertexts or forge
        signatures, especially in scenarios involving API endpoints
        processing Json Web Encryption messages.
        The fix disables RSA_PKCS1_PADDING for crypto.privateDecrypt(), and
        includes a security revert flag that can be used to restore support
        (and the vulnerability).

    CVE-2024-22025

        It was discovered that Node.js was vulnerable to Denial of Service
        by resource exhaustion in fetch() brotli decoding.

    For Debian 10 buster, these problems have been fixed in version
    10.24.0~dfsg-1~deb10u4.

    We recommend that you upgrade your nodejs packages.

    For the detailed security status of nodejs please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/nodejs

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nodejs");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30590");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46809");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22025");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/nodejs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libnode-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnode-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnode64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nodejs-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'libnode-dev', 'reference': '10.24.0~dfsg-1~deb10u4'},
    {'release': '10.0', 'prefix': 'libnode64', 'reference': '10.24.0~dfsg-1~deb10u4'},
    {'release': '10.0', 'prefix': 'nodejs', 'reference': '10.24.0~dfsg-1~deb10u4'},
    {'release': '10.0', 'prefix': 'nodejs-doc', 'reference': '10.24.0~dfsg-1~deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnode-dev / libnode64 / nodejs / nodejs-doc');
}
