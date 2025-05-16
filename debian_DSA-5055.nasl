#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5055. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157263);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2021-3995", "CVE-2021-3996");

  script_name(english:"Debian DSA-5055-1 : util-linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5055 advisory.

    The Qualys Research Labs discovered two vulnerabilities in util-linux's libmount. These flaws allow an
    unprivileged user to unmount other users' filesystems that are either world-writable themselves or mounted
    in a world-writable directory (CVE-2021-3996), or to unmount FUSE filesystems that belong to certain other
    users (CVE-2021-3995). For the stable distribution (bullseye), these problems have been fixed in version
    2.36.1-8+deb11u1. We recommend that you upgrade your util-linux packages. For the detailed security status
    of util-linux please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/util-linux

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/util-linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5055");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3995");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3996");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/util-linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the util-linux packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.36.1-8+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3996");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdextrautils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eject-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fdisk-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libblkid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libblkid1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfdisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfdisk1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmount-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmount1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmartcols-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmartcols1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuuid1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rfkill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uuid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uuid-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'bsdextrautils', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'bsdutils', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'eject', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'eject-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'fdisk', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'fdisk-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libblkid-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libblkid1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libblkid1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libfdisk-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libfdisk1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libfdisk1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libmount-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libmount1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libmount1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libsmartcols-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libsmartcols1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libsmartcols1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libuuid1', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'libuuid1-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'mount', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'rfkill', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'util-linux', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'util-linux-locales', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'util-linux-udeb', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'uuid-dev', 'reference': '2.36.1-8+deb11u1'},
    {'release': '11.0', 'prefix': 'uuid-runtime', 'reference': '2.36.1-8+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bsdextrautils / bsdutils / eject / eject-udeb / fdisk / fdisk-udeb / etc');
}
