#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3782. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192962);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2021-37600", "CVE-2024-28085");

  script_name(english:"Debian dla-3782 : bsdutils - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3782 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3782-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    April 07, 2024                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : util-linux
    Version        : 2.33.1-0.1+deb10u1
    CVE ID         : CVE-2021-37600 CVE-2024-28085
    Debian Bug     : 826596 991619 1067849

    CVE-2024-28085

        Skyler Ferrante discovered that the wall(1) utility found in
        util-linux, a collection of system utilities for Linux, does not
        filter escape sequences from command line arguments.  This allows
        unprivileged local users to put arbitrary text on other users
        terminals if mesg is set to y and the wall executable is setgid,
        which could lead to information disclosure.

        With this update the wall executable is no longer installed setgid
        tty.

    CVE-2021-37600

        Kihong Heo found an integer overflow which can potentially lead to
        buffer overflow if an attacker were able to use system resources in
        a way that leads to a large number in the /proc/sysvipc/sem file.
        NOTE: this is issue is unexploitable in GNU C Library environments,
        and possibly in all realistic environments.

    For Debian 10 buster, these problems have been fixed in version
    2.33.1-0.1+deb10u1.

    We recommend that you upgrade your util-linux packages.

    For the detailed security status of util-linux please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/util-linux

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/util-linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37600");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-28085");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/util-linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the bsdutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37600");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libblkid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfdisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmount-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmartcols-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rfkill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uuid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uuid-runtime");
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
    {'release': '10.0', 'prefix': 'bsdutils', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'fdisk', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libblkid-dev', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libblkid1', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libfdisk-dev', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libfdisk1', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libmount-dev', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libmount1', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libsmartcols-dev', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libsmartcols1', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libuuid1', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'mount', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'rfkill', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'util-linux', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'util-linux-locales', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'uuid-dev', 'reference': '2.33.1-0.1+deb10u1'},
    {'release': '10.0', 'prefix': 'uuid-runtime', 'reference': '2.33.1-0.1+deb10u1'}
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
    severity   : SECURITY_NOTE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bsdutils / fdisk / libblkid-dev / libblkid1 / libfdisk-dev / libfdisk1 / etc');
}
