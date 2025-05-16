#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3559. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181187);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2019-13115", "CVE-2019-17498", "CVE-2020-22218");

  script_name(english:"Debian dla-3559 : libssh2-1 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3559 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3559-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    September 08, 2023                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libssh2
    Version        : 1.8.0-2.1+deb10u1
    CVE ID         : CVE-2019-13115 CVE-2019-17498 CVE-2020-22218
    Debian Bug     : 932329 943562

    Vulnerabilities were found in libssh2, a client-side C library
    implementing the SSH2 protocol, which could lead to denial of service or
    remote information disclosure.

    CVE-2019-13115

        Kevin Backhouse discovered an integer overflow vulnerability in kex.c's
        kex_method_diffie_hellman_group_exchange_sha256_key_exchange()
        function, which could lead to an out-of-bounds read in the way
        packets are read from the server.  A remote attacker who compromises
        an SSH server may be able to disclose sensitive information or cause
        a denial of service condition on the client system when a user
        connects to the server.

    CVE-2019-17498

        Kevin Backhouse discovered that the SSH_MSG_DISCONNECT logic in
        packet.c has an integer overflow in a bounds check, thereby enabling
        an attacker to specify an arbitrary (out-of-bounds) offset for a
        subsequent memory read.  A malicious SSH server may be able to
        disclose sensitive information or cause a denial of service
        condition on the client system when a user connects to the server.

    CVE-2020-22218

        An issue was discovered in function _libssh2_packet_add(), which
        could allow attackers to access out of bounds memory.

    For Debian 10 buster, these problems have been fixed in version
    1.8.0-2.1+deb10u1.

    We recommend that you upgrade your libssh2 packages.

    For the detailed security status of libssh2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libssh2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libssh2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13115");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-17498");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-22218");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libssh2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libssh2-1 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17498");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh2-1-dev");
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
    {'release': '10.0', 'prefix': 'libssh2-1', 'reference': '1.8.0-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libssh2-1-dev', 'reference': '1.8.0-2.1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libssh2-1 / libssh2-1-dev');
}
