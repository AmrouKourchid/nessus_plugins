#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4942. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151833);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2021-33910");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"Debian DSA-4942-1 : systemd - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dsa-4942
advisory.

    The Qualys Research Labs discovered that an attacker-controlled allocation using the alloca() function
    could result in memory corruption, allowing to crash systemd and hence the entire operating system.
    Details can be found in the Qualys advisory at https://www.qualys.com/2021/07/20/cve-2021-33910/denial-of-
    service-systemd.txt For the stable distribution (buster), this problem has been fixed in version
    241-7~deb10u8. We recommend that you upgrade your systemd packages. For the detailed security status of
    systemd please refer to its security tracker page at: https://security-tracker.debian.org/tracker/systemd

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/systemd");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4942");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33910");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/systemd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the systemd packages.

For the stable distribution (buster), this problem has been fixed in version 241-7~deb10u8.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33910");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'libnss-myhostname', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'libnss-mymachines', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'libnss-resolve', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'libnss-systemd', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'libpam-systemd', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'libsystemd-dev', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'libsystemd0', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'libudev-dev', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'libudev1', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'systemd', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'systemd-container', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'systemd-coredump', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'systemd-journal-remote', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'systemd-sysv', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'systemd-tests', 'reference': '241-7~deb10u8'},
    {'release': '10.0', 'prefix': 'udev', 'reference': '241-7~deb10u8'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-myhostname / libnss-mymachines / libnss-resolve / etc');
}
