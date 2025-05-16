#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3681. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(186524);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-37703", "CVE-2022-37705", "CVE-2023-30577");

  script_name(english:"Debian dla-3681 : amanda-client - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3681 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3681-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    December 03, 2023                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : amanda
    Version        : 1:3.5.1-2+deb10u2
    CVE ID         : CVE-2022-37703 CVE-2022-37705 CVE-2023-30577
    Debian Bug     : 1021017 1029829 1055253

    Multiple vulnerabilties have been found in Amanda,a backup system
    designed to archive many computers on a network to a single
    large-capacity tape drive. The vulnerabilties potentially allows local
    privilege escalation from the backup user to root or leak information
    whether a directory exists in the filesystem.

    CVE-2022-37703

        In Amanda 3.5.1, an information leak vulnerability was found in the
        calcsize SUID binary. An attacker can abuse this vulnerability to
        know if a directory exists or not anywhere in the fs. The binary
        will use `opendir()` as root directly without checking the path,
        letting the attacker provide an arbitrary path.


    CVE-2022-37705

        A privilege escalation flaw was found in Amanda 3.5.1 in which the
        backup user can acquire root privileges. The vulnerable component is
        the runtar SUID program, which is a wrapper to run /usr/bin/tar with
        specific arguments that are controllable by the attacker. This
        program mishandles the arguments passed to tar binary.

    CVE-2023-30577

        The SUID binary runtar can accept the possibly malicious GNU tar
        options if fed with some non-argument option starting with
        --exclude (say --exclude-vcs). The following option will be
        accepted as good and it could be an option passing some
        script/binary that would be executed with root permissions.

    For Debian 10 buster, these problems have been fixed in version
    1:3.5.1-2+deb10u2.

    We recommend that you upgrade your amanda packages.

    For the detailed security status of amanda please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/amanda

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/amanda");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37703");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30577");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/amanda");
  script_set_attribute(attribute:"solution", value:
"Upgrade the amanda-client packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30577");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:amanda-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:amanda-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:amanda-server");
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
    {'release': '10.0', 'prefix': 'amanda-client', 'reference': '1:3.5.1-2+deb10u2'},
    {'release': '10.0', 'prefix': 'amanda-common', 'reference': '1:3.5.1-2+deb10u2'},
    {'release': '10.0', 'prefix': 'amanda-server', 'reference': '1:3.5.1-2+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'amanda-client / amanda-common / amanda-server');
}
