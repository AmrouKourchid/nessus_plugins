#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5650. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192730);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2024-28085");

  script_name(english:"Debian dsa-5650 : bsdextrautils - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5650
advisory.

  - wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to
    be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are
    blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where
    this leads to account takeover. (CVE-2024-28085)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/util-linux");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-28085");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/util-linux");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/util-linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the bsdextrautils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28085");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/31");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:util-linux-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uuid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uuid-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'bsdextrautils', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'bsdutils', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'eject', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'eject-udeb', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'fdisk', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'fdisk-udeb', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libblkid-dev', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libblkid1', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libblkid1-udeb', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libfdisk-dev', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libfdisk1', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libfdisk1-udeb', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libmount-dev', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libmount1', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libmount1-udeb', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libsmartcols-dev', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libsmartcols1', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libsmartcols1-udeb', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libuuid1', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'libuuid1-udeb', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'mount', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'rfkill', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'util-linux', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'util-linux-locales', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'util-linux-udeb', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'uuid-dev', 'reference': '2.36.1-8+deb11u2'},
    {'release': '11.0', 'prefix': 'uuid-runtime', 'reference': '2.36.1-8+deb11u2'},
    {'release': '12.0', 'prefix': 'bsdextrautils', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'bsdutils', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'eject', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'eject-udeb', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'fdisk', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'fdisk-udeb', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libblkid-dev', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libblkid1', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libblkid1-udeb', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libfdisk-dev', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libfdisk1', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libfdisk1-udeb', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libmount-dev', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libmount1', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libmount1-udeb', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libsmartcols-dev', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libsmartcols1', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libsmartcols1-udeb', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libuuid1', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libuuid1-udeb', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'mount', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'rfkill', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'util-linux', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'util-linux-extra', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'util-linux-locales', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'util-linux-udeb', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'uuid-dev', 'reference': '2.38.1-5+deb12u1'},
    {'release': '12.0', 'prefix': 'uuid-runtime', 'reference': '2.38.1-5+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bsdextrautils / bsdutils / eject / eject-udeb / fdisk / fdisk-udeb / etc');
}
