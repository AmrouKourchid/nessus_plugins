#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4031. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(214705);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/28");

  script_cve_id("CVE-2020-5260", "CVE-2024-50349", "CVE-2024-52006");

  script_name(english:"Debian dla-4031 : git - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4031 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4031-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Sean Whitton
    January 28, 2025                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : git
    Version        : 1:2.30.2-1+deb11u4
    CVE ID         : CVE-2024-50349 CVE-2024-52006
    Debian Bug     : 1093042

    Multiple vulnerabilities were discovered in git, a fast, scalable and
    distributed revision control system.

    CVE-2024-50349

        When Git asks for credentials via a terminal prompt (i.e. without
        using any credential helper), it prints out the host name for which
        the user is expected to provide a username and/or a password.  At
        this stage, any URL-encoded parts have been decoded already, and are
        printed verbatim.  This could allow attackers to craft URLs that
        contain ANSI escape sequences that the terminal interpret to confuse
        users e.g. into providing passwords for trusted Git hosting sites
        when in fact they are then sent to untrusted sites that are under
        the attacker's control.

    CVE-2024-52006

        Git defines a line-based protocol that is used to exchange
        information between Git and Git credential helpers.  Some ecosystems
        (most notably, .NET and node.js) interpret single Carriage Return
        characters as newlines, which renders the protections against
        CVE-2020-5260 incomplete for credential helpers that treat Carriage
        Returns in this way.

    For Debian 11 bullseye, these problems have been fixed in version
    1:2.30.2-1+deb11u4.

    We recommend that you upgrade your git packages.

    For the detailed security status of git please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/git

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/git");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-5260");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50349");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52006");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/git");
  script_set_attribute(attribute:"solution", value:
"Upgrade the git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5260");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-52006");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-daemon-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-daemon-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'release': '11.0', 'prefix': 'git', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-all', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-cvs', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-daemon-run', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-daemon-sysvinit', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-doc', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-el', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-email', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-gui', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-man', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-mediawiki', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'git-svn', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'gitk', 'reference': '1:2.30.2-1+deb11u4'},
    {'release': '11.0', 'prefix': 'gitweb', 'reference': '1:2.30.2-1+deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git / git-all / git-cvs / git-daemon-run / git-daemon-sysvinit / etc');
}
