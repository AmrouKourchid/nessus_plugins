#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3668. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(186290);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-40660", "CVE-2023-40661");

  script_name(english:"Debian dla-3668 : opensc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3668 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3668-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    November 27, 2023                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : opensc
    Version        : 0.19.0-1+deb10u3
    CVE ID         : CVE-2023-40660 CVE-2023-40661
    Debian Bug     : 1055521 1055522

    Vulnerabilities were found in opensc, a set of libraries and utilities
    to access smart cards, which could lead to application crash or PIN
    bypass.

    CVE-2023-40660

        When the token/card was plugged into the computer and authenticated
        from one process, it could be used to provide cryptographic
        operations from different process when the empty, zero-length PIN
        and the token can track the login status using some of its
        internals.  This is dangerous for OS logon/screen unlock and small
        tokens that are plugged permanently to the computer.

        The bypass was removed and explicit logout implemented for most of
        the card drivers to prevent leaving unattended logged-in tokens.

    CVE-2023-40661

        This advisory summarizes automatically reported issues from dynamic
        analyzers reports in pkcs15-init that are security relevant.

          * stack buffer overflow in sc_pkcs15_get_lastupdate() in pkcs15init;
          * heap buffer overflow in setcos_create_key() in pkcs15init;
          * heap buffer overflow in cosm_new_file() in pkcs15init;
          * stack buffer overflow in cflex_delete_file() in pkcs15init;
          * heap buffer overflow in sc_hsm_write_ef() in pkcs15init;
          * stack buffer overflow while parsing pkcs15 profile files;
          * stack buffer overflow in muscle driver in pkcs15init; and
          * stack buffer overflow in cardos driver in pkcs15init.

        All of these require physical access to the computer at the time
        user or administrator would be enrolling the cards (generating keys
        and loading certificates, other card/token management) operations.
        The attack requires crafted USB device or smart card that would
        present the system with specially crafted responses to the APDUs so
        they are considered a high-complexity and low-severity.  This issue
        is not exploitable just by using a PKCS#11 module as done in most of
        the end-user deployments.

    For Debian 10 buster, these problems have been fixed in version
    0.19.0-1+deb10u3.

    We recommend that you upgrade your opensc packages.

    For the detailed security status of opensc please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/opensc

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/opensc");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40660");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40661");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/opensc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the opensc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensc-pkcs11");
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
    {'release': '10.0', 'prefix': 'opensc', 'reference': '0.19.0-1+deb10u3'},
    {'release': '10.0', 'prefix': 'opensc-pkcs11', 'reference': '0.19.0-1+deb10u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opensc / opensc-pkcs11');
}
