#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3910. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(208201);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2022-1304");

  script_name(english:"Debian dla-3910 : comerr-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dla-3910
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3910-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    October 04, 2024                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : e2fsprogs
    Version        : 1.46.2-2+deb11u1
    CVE ID         : CVE-2022-1304
    Debian Bug     : 1010263

    An out-of-bounds read/write vulnerability has been fixed in the e2fsck
    tool of the ext2/ext3/ext4 file system utilities e2fsprogs.

    For Debian 11 bullseye, this problem has been fixed in version
    1.46.2-2+deb11u1.

    We recommend that you upgrade your e2fsprogs packages.

    For the detailed security status of e2fsprogs please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/e2fsprogs

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/e2fsprogs");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1304");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/e2fsprogs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the comerr-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:comerr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsck-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse2fs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcom-err2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libext2fs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libext2fs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libss2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:logsave");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ss-dev");
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
    {'release': '11.0', 'prefix': 'comerr-dev', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'e2fsck-static', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'e2fsprogs', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'e2fsprogs-l10n', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'e2fsprogs-udeb', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'fuse2fs', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libcom-err2', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libext2fs-dev', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libext2fs2', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libss2', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'logsave', 'reference': '1.46.2-2+deb11u1'},
    {'release': '11.0', 'prefix': 'ss-dev', 'reference': '1.46.2-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'comerr-dev / e2fsck-static / e2fsprogs / e2fsprogs-l10n / etc');
}
