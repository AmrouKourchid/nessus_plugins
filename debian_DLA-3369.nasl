#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3369. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(173457);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2019-16884",
    "CVE-2019-19921",
    "CVE-2021-30465",
    "CVE-2022-29162",
    "CVE-2023-27561"
  );

  script_name(english:"Debian dla-3369 : golang-github-opencontainers-runc-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3369 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3369-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Sylvain Beucler
    March 27, 2023                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : runc
    Version        : 1.0.0~rc6+dfsg1-3+deb10u2
    CVE ID         : CVE-2019-16884 CVE-2019-19921 CVE-2021-30465 CVE-2022-29162
                     CVE-2023-27561
    Debian Bug     : 942026 988768

    Multiple vulnerabilities were discovered in runc, the Open Container
    Project runtime, which is often used with virtualization environments
    such as Docker. Malicious Docker images or OCI bundles could breach
    isolation.

    CVE-2019-16884

        runc, as used in Docker and other products, allows AppArmor and
        SELinux restriction bypass because libcontainer/rootfs_linux.go
        incorrectly checks mount targets, and thus a malicious Docker
        image can mount over a /proc directory.

    CVE-2019-19921

        runc has Incorrect Access Control leading to Escalation of
        Privileges, related to libcontainer/rootfs_linux.go. To exploit
        this, an attacker must be able to spawn two containers with custom
        volume-mount configurations, and be able to run custom
        images. (This vulnerability does not affect Docker due to an
        implementation detail that happens to block the attack.)

    CVE-2021-30465

        runc allows a Container Filesystem Breakout via Directory
        Traversal. To exploit the vulnerability, an attacker must be able
        to create multiple containers with a fairly specific mount
        configuration. The problem occurs via a symlink-exchange attack
        that relies on a race condition.

    CVE-2022-29162

        `runc exec --cap` created processes with non-empty inheritable
        Linux process capabilities, creating an atypical Linux environment
        and enabling programs with inheritable file capabilities to
        elevate those capabilities to the permitted set during
        execve(2). This bug did not affect the container security sandbox
        as the inheritable set never contained more capabilities than were
        included in the container's bounding set.

    CVE-2023-27561

        CVE-2019-19921 was re-introduced by the fix for CVE-2021-30465.

    For Debian 10 buster, this problem has been fixed in version
    1.0.0~rc6+dfsg1-3+deb10u2.

    We recommend that you upgrade your runc packages.

    For the detailed security status of runc please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/runc

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/runc");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-19921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30465");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29162");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27561");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/runc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the golang-github-opencontainers-runc-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-github-opencontainers-runc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:runc");
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
    {'release': '10.0', 'prefix': 'golang-github-opencontainers-runc-dev', 'reference': '1.0.0~rc6+dfsg1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'runc', 'reference': '1.0.0~rc6+dfsg1-3+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-opencontainers-runc-dev / runc');
}
