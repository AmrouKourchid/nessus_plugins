#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4004. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(213413);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/28");

  script_cve_id(
    "CVE-2021-34193",
    "CVE-2021-42778",
    "CVE-2021-42779",
    "CVE-2021-42780",
    "CVE-2021-42781",
    "CVE-2021-42782",
    "CVE-2023-2977",
    "CVE-2023-5992",
    "CVE-2023-40660",
    "CVE-2023-40661",
    "CVE-2024-1454",
    "CVE-2024-8443",
    "CVE-2024-45615",
    "CVE-2024-45616",
    "CVE-2024-45617",
    "CVE-2024-45618",
    "CVE-2024-45619",
    "CVE-2024-45620"
  );

  script_name(english:"Debian dla-4004 : opensc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4004 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4004-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    December 28, 2024                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : opensc
    Version        : 0.21.0-1+deb11u1
    CVE ID         : CVE-2021-34193 CVE-2021-42778 CVE-2021-42779 CVE-2021-42780
                     CVE-2021-42781 CVE-2021-42782 CVE-2023-2977 CVE-2023-5992
                     CVE-2023-40660 CVE-2023-40661 CVE-2024-1454 CVE-2024-8443
                     CVE-2024-45615 CVE-2024-45616 CVE-2024-45617 CVE-2024-45618
                     CVE-2024-45619 CVE-2024-45620
    Debian Bug     : 1037021 1055521 1055522 1064189 1082853 1082859 1082860
                     1082861 1082862 1082863 1082864

    Multiple vulnerabilities were found in opensc, a set of libraries and
    utilities to access smart cards, which could lead to application crash,
    information leak, or PIN bypass.

    CVE-2021-34193

        Multiple stack overflow vulnerabilities were discovered in OpenSC
        smart card middleware via crafted responses to APDUs.

    CVE-2021-42778

        A heap double free issue was found in sc_pkcs15_free_tokeninfo().

    CVE-2021-42779

        A heap use after free issue was found in sc_file_valid().

    CVE-2021-42780

        A use after return issue was found in the insert_pin() function,
        which could potentially crash programs using the library.

    CVE-2021-42781

        Multiple heap buffer overflow issues were found in
        pkcs15-oberthur.c, which could potentially crash programs using the
        library.

    CVE-2021-42782

        Multiple buffer overflow issues were found in various places, which
        could potentially crash programs using the library.

    CVE-2023-2977

        A buffer overrun vulnerability was found in pkcs15's
        cardos_have_verifyrc_package().  When supplying a smart card package
        with malformed ASN.1 context, an attacker can trigger a crash or
        information leak via heap-based buffer out-of-bound read.

    CVE-2023-5992

         Alicja Karion discovered that the code handling the PKCS#1.5
         encryption padding removal was not implemented in side-channel
         resistant way, which can lead to decryption of previously captured
         RSA ciphertexts and forging of signatures based on the timing data
         (Marvin attack).

    CVE-2023-40660

        Deepanjan Pal discovered a potential PIN bypass with empty PIN.
        When the token/card was plugged into the computer and authenticated
        from one process, it could be used to provide cryptographic
        operations from different process when the empty, zero-length PIN
        was provided.

    CVE-2023-40661

        Multiple memory vulnerabilities were found by dynamic analyzers in
        pkcs15-init.

    CVE-2024-1454

        A memory use after free issue was found in AuthentIC driver when
        updating token info.

    CVE-2024-8443

        An heap buffer overflow issue was found in OpenPGP driver during key
        generation.

    CVE-2024-45615

        Matteo Marini discovered multiple uses of uninitialized values in
        libopensc and pkcs15init.

    CVE-2024-45616

        Matteo Marini discovered multiple uses of uninitialized values after
        incorrect check or usage of APDU response values in libopensc.

    CVE-2024-45617

        Matteo Marini discovered multiple uses of uninitialized values after
        incorrect or missing checking return values of functions in
        libopensc.

    CVE-2024-45618

        Matteo Marini discovered multiple uses of uninitialized values after
        incorrect or missing checking return values of functions in
        pkcs15init.

    CVE-2024-45619

        Matteo Marini discovered multiple incorrect handling of length of
        buffers or files in libopensc, which could result in application
        crash or information leak.  When buffers are partially filled with
        data, uninitialized parts of the buffer may be incorrectly accessed.

    CVE-2024-45620

        Matteo Marini discovered multiple incorrect handling of length of
        buffers or files in pkcs15init, which could result in application
        crash or information leak.  When buffers are partially filled with
        data, uninitialized parts of the buffer may be incorrectly accessed.

    For Debian 11 bullseye, these problems have been fixed in version
    0.21.0-1+deb11u1.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-34193");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42778");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42782");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2977");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40660");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40661");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5992");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-1454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45615");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45618");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45620");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-8443");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/opensc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the opensc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42782");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2977");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensc-pkcs11");
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
    {'release': '11.0', 'prefix': 'opensc', 'reference': '0.21.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'opensc-pkcs11', 'reference': '0.21.0-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opensc / opensc-pkcs11');
}
