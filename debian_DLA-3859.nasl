#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3859. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206418);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/02");

  script_cve_id("CVE-2023-7008", "CVE-2023-50387", "CVE-2023-50868");

  script_name(english:"Debian dla-3859 : libnss-myhostname - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3859 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3859-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    September 02, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : systemd
    Version        : 247.3-7+deb11u6
    CVE ID         : CVE-2023-7008 CVE-2023-50387 CVE-2023-50868
    Debian Bug     : 1059278

    Multiple vulnerabilities have been fixed in systemd, the default init
    system in Debian, when using systemd-resolved with DNSSEC.

    CVE-2023-7008

        Don't accept records of DNSSEC-signed domains when they have no signature.

    CVE-2023-50387

        DNSSEC denial of service (CPU consumption)

    CVE-2023-50868

        DNSSEC denial of service (CPU consumption)

    For Debian 11 bullseye, these problems have been fixed in version
    247.3-7+deb11u6.

    We recommend that you upgrade your systemd packages.

    For the detailed security status of systemd please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/systemd

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/systemd");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50387");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50868");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-7008");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/systemd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libnss-myhostname packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-7008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/02");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libudev1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd-timesyncd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udev-udeb");
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
    {'release': '11.0', 'prefix': 'libnss-myhostname', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libnss-mymachines', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libnss-resolve', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libnss-systemd', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libpam-systemd', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libsystemd-dev', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libsystemd0', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libudev-dev', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libudev1', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'libudev1-udeb', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'systemd', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'systemd-container', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'systemd-coredump', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'systemd-journal-remote', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'systemd-sysv', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'systemd-tests', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'systemd-timesyncd', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'udev', 'reference': '247.3-7+deb11u6'},
    {'release': '11.0', 'prefix': 'udev-udeb', 'reference': '247.3-7+deb11u6'}
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
