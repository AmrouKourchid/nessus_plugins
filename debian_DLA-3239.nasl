#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3239. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168740);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-24765",
    "CVE-2022-29187",
    "CVE-2022-39253",
    "CVE-2022-39260"
  );

  script_name(english:"Debian dla-3239 : git - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3239 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3239-2                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Sylvain Beucler
    December 14, 2022                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : git
    Version        : 1:2.20.1-2+deb10u6

    In rare conditions, the previous git update released as DLA-3239-1
    could generate a segmentation fault, which prevented its availability
    on armhf architecture. This update addresses this issue. For reference
    the original advisory text follows.

    Multiple issues were found in Git, a distributed revision control
    system. An attacker may cause other local users into executing
    arbitrary commands, leak information from the local filesystem, and
    bypass restricted shell.

    Note: Due to new security checks, access to repositories owned and
    accessed by different local users may now be rejected by Git; in case
    changing ownership is not practical, git displays a way to bypass
    these checks using the new 'safe.directory' configuration entry.

    CVE-2022-24765

        Git is not checking the ownership of directories in a local
        multi-user system when running commands specified in the local
        repository configuration.  This allows the owner of the repository
        to cause arbitrary commands to be executed by other users who
        access the repository.

    CVE-2022-29187

        An unsuspecting user could still be affected by the issue reported
        in CVE-2022-24765, for example when navigating as root into a
        shared tmp directory that is owned by them, but where an attacker
        could create a git repository.

    CVE-2022-39253

        Exposure of sensitive information to a malicious actor. When
        performing a local clone (where the source and target of the clone
        are on the same volume), Git copies the contents of the source's
        `$GIT_DIR/objects` directory into the destination by either
        creating hardlinks to the source contents, or copying them (if
        hardlinks are disabled via `--no-hardlinks`). A malicious actor
        could convince a victim to clone a repository with a symbolic link
        pointing at sensitive information on the victim's machine.

    CVE-2022-39260

        `git shell` improperly uses an `int` to represent the number of
        entries in the array, allowing a malicious actor to intentionally
        overflow the return value, leading to arbitrary heap
        writes. Because the resulting array is then passed to `execv()`,
        it is possible to leverage this attack to gain remote code
        execution on a victim machine.

    For Debian 10 buster, this problem has been fixed in version
    1:2.20.1-2+deb10u6.

    We recommend that you upgrade your git packages.

    For the detailed security status of git please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/git

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/git");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29187");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39253");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39260");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/git");
  script_set_attribute(attribute:"solution", value:
"Upgrade the git packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29187");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39260");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/14");

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
    {'release': '10.0', 'prefix': 'git', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-all', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-cvs', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-daemon-run', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-daemon-sysvinit', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-doc', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-el', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-email', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-gui', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-man', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-mediawiki', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'git-svn', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'gitk', 'reference': '1:2.20.1-2+deb10u6'},
    {'release': '10.0', 'prefix': 'gitweb', 'reference': '1:2.20.1-2+deb10u6'}
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
