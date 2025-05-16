#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4114. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(233873);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2013-20001", "CVE-2023-49298");

  script_name(english:"Debian dla-4114 : libnvpair3linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4114 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4114-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Daniel Leidert
    April 05, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : zfs-linux
    Version        : 2.0.3-9+deb11u2
    CVE ID         : CVE-2013-20001 CVE-2023-49298
    Debian Bug     : 1056752 1059322

    Multiple vulnerabilities were found in zfs-linux, the OpenZFS
    filesystem for Linux.

    CVE-2013-20001

       When an NFS share is exported to IPv6 addresses via the sharenfs
       feature, there is a silent failure to parse the IPv6 address data, and
       access is allowed to everyone. IPv6 restrictions from the configuration
       are not applied. With the fix, recognize when the host part of a
       sharenfs attribute is an ipv6 Literal, and pass that through without
       modification.

    CVE-2023-49298

       Check dnode and its data for dirtiness to prevent applications from
       inadvertently replacing file contents with zero-valued bytes and
       thus potentially disabling security mechanisms.

    For Debian 11 bullseye, these problems have been fixed in version
    2.0.3-9+deb11u2.

    We recommend that you upgrade your zfs-linux packages.

    For the detailed security status of zfs-linux please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/zfs-linux

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/zfs-linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2013-20001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49298");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/zfs-linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libnvpair3linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-20001");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-49298");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnvpair3linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-zfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuutil3linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzfs4linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzfsbootenv1linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzfslinux-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzpool4linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pyzfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pyzfs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spl-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zfs-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zfs-dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zfs-initramfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zfs-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zfs-zed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zfsutils-linux");
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
    {'release': '11.0', 'prefix': 'libnvpair3linux', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'libpam-zfs', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'libuutil3linux', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'libzfs4linux', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'libzfsbootenv1linux', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'libzfslinux-dev', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'libzpool4linux', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'python3-pyzfs', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'pyzfs-doc', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'spl', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'spl-dkms', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'zfs-dkms', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'zfs-dracut', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'zfs-initramfs', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'zfs-test', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'zfs-zed', 'reference': '2.0.3-9+deb11u2'},
    {'release': '11.0', 'prefix': 'zfsutils-linux', 'reference': '2.0.3-9+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnvpair3linux / libpam-zfs / libuutil3linux / libzfs4linux / etc');
}
