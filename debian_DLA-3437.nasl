#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3437. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176464);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2019-14889", "CVE-2023-1667");
  script_xref(name:"IAVA", value:"2023-A-0517-S");

  script_name(english:"Debian dla-3437 : libssh-4 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3437 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3437-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    May 29, 2023                                  https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libssh
    Version        : 0.8.7-1+deb10u2
    CVE ID         : CVE-2019-14889 CVE-2023-1667
    Debian Bug     : 946548 1035832

    Two security issues have been discovered in libssh, a tiny C SSH
    library, which may allows an remote authenticated user to cause a denial
    of service or inject arbitrary commands.

    CVE-2019-14889

        A flaw was found with the libssh API function ssh_scp_new() in
        versions before 0.9.3 and before 0.8.8. When the libssh SCP client
        connects to a server, the scp command, which includes a
        user-provided path, is executed on the server-side. In case the
        library is used in a way where users can influence the third
        parameter of the function, it would become possible for an attacker
        to inject arbitrary commands, leading to a compromise of the remote
        target.

    CVE-2023-1667

        A NULL pointer dereference was found In libssh during re-keying with
        algorithm guessing. This issue may allow an authenticated client to
        cause a denial of service.

    For Debian 10 buster, these problems have been fixed in version
    0.8.7-1+deb10u2.

    We recommend that you upgrade your libssh packages.

    For the detailed security status of libssh please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libssh

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libssh");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1667");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libssh");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libssh-4 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14889");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh-gcrypt-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh-gcrypt-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    {'release': '10.0', 'prefix': 'libssh-4', 'reference': '0.8.7-1+deb10u2'},
    {'release': '10.0', 'prefix': 'libssh-dev', 'reference': '0.8.7-1+deb10u2'},
    {'release': '10.0', 'prefix': 'libssh-doc', 'reference': '0.8.7-1+deb10u2'},
    {'release': '10.0', 'prefix': 'libssh-gcrypt-4', 'reference': '0.8.7-1+deb10u2'},
    {'release': '10.0', 'prefix': 'libssh-gcrypt-dev', 'reference': '0.8.7-1+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libssh-4 / libssh-dev / libssh-doc / libssh-gcrypt-4 / etc');
}
