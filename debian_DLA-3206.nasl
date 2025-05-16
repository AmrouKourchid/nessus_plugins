#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3206. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168205);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2019-14870",
    "CVE-2021-3671",
    "CVE-2021-44758",
    "CVE-2022-3437",
    "CVE-2022-41916",
    "CVE-2022-42898",
    "CVE-2022-44640"
  );

  script_name(english:"Debian dla-3206 : heimdal-clients - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3206 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3206-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    November 26, 2022                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : heimdal
    Version        : 7.5.0+dfsg-3+deb10u1
    CVE ID         : CVE-2019-14870 CVE-2021-3671 CVE-2021-44758 CVE-2022-3437
                     CVE-2022-41916 CVE-2022-42898 CVE-2022-44640
    Debian Bug     : 946786 996586 1024187

    Multiple security vulnerabilities were discovered in heimdal, an
    implementation of the Kerberos 5 authentication protocol, which may
    result in denial of service, information disclosure, or remote code
    execution.

    CVE-2019-14870

        Isaac Boukris reported that the Heimdal KDC before 7.7.1 does not
        apply delegation_not_allowed (aka not-delegated) user attributes for
        S4U2Self.  Instead the forwardable flag is set even if the
        impersonated client has the not-delegated flag set.

    CVE-2021-3671

        Joseph Sutton discovered that the Heimdal KDC before 7.7.1 does not
        check for missing missing sname in TGS-REQ (Ticket Granting Server -
        Request) before before dereferencing.  An authenticated user could
        use this flaw to crash the KDC.

    CVE-2021-44758

        It was discovered that Heimdal is prone to a NULL dereference in
        acceptors when the initial SPNEGO token has no acceptable
        mechanisms, which may result in denial of service for a server
        application that uses the Simple and Protected GSSAPI Negotiation
        Mechanism (SPNEGO).

    CVE-2022-3437

        Evgeny Legerov reported that the DES and Triple-DES decryption
        routines in the Heimdal GSSAPI library before 7.7.1 were prone to
        buffer overflow on malloc() allocated memory when presented with a
        maliciously small packet.  In addition, the Triple-DES and RC4
        (arcfour) decryption routine were prone to non-constant time leaks,
        which could potentially yield to a leak of secret key material when
        using these ciphers.

    CVE-2022-41916

        It was discovered that Heimdal's PKI certificate validation library
        before 7.7.1 can under some circumstances perform an out-of-bounds
        memory access when normalizing Unicode, which may result in denial
        of service.

    CVE-2022-42898

        Greg Hudson discovered an integer multiplication overflow in the
        Privilege Attribute Certificate (PAC) parsing routine, which may
        result in denial of service for Heimdal KDCs and possibly Heimdal
        servers (e.g., via GSS-API) on 32-bit systems.

    CVE-2022-44640

        Douglas Bagnall and the Heimdal maintainers independently discovered
        that Heimdal's ASN.1 compiler before 7.7.1 generates code that
        allows specially crafted DER encodings of CHOICEs to invoke the
        wrong free() function on the decoded structure upon decode error,
        which may result in remote code execution in the Heimdal KDC and
        possibly the Kerberos client, the X.509 library, and other
        components as well.

    For Debian 10 buster, these problems have been fixed in version
    7.5.0+dfsg-3+deb10u1.

    We recommend that you upgrade your heimdal packages.

    For the detailed security status of heimdal please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/heimdal

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/heimdal");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14870");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3671");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44758");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3437");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44640");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/heimdal");
  script_set_attribute(attribute:"solution", value:
"Upgrade the heimdal-clients packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14870");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-44640");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasn1-8-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgssapi3-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhcrypto4-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdb9-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheimbase1-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheimntlm0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhx509-5-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5clnt7-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5srv8-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkafs0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdc2-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-26-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libotp0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libroken18-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsl0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwind0-heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'heimdal-clients', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-dev', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-docs', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-kcm', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-kdc', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-multidev', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-servers', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libasn1-8-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libgssapi3-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libhcrypto4-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdb9-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libheimbase1-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libheimntlm0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libhx509-5-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkadm5clnt7-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkadm5srv8-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkafs0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkdc2-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkrb5-26-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libotp0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libroken18-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libsl0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libwind0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'heimdal-clients / heimdal-dev / heimdal-docs / heimdal-kcm / etc');
}
