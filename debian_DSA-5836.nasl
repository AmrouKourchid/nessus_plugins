#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5836. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(213392);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/26");

  script_cve_id(
    "CVE-2023-28746",
    "CVE-2023-46841",
    "CVE-2023-46842",
    "CVE-2024-2193",
    "CVE-2024-2201",
    "CVE-2024-31142",
    "CVE-2024-31143",
    "CVE-2024-31145",
    "CVE-2024-31146",
    "CVE-2024-45817",
    "CVE-2024-45818",
    "CVE-2024-45819"
  );

  script_name(english:"Debian dsa-5836 : libxen-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5836 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5836-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    December 26, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : xen
    CVE ID         : CVE-2023-28746 CVE-2023-46841 CVE-2023-46842 CVE-2024-2193
                     CVE-2024-2201 CVE-2024-31142 CVE-2024-31143 CVE-2024-31145
                     CVE-2024-31146 CVE-2024-45817 CVE-2024-45818 CVE-2024-45819

    Multiple vulnerabilities have been discovered in the Xen hypervisor,
    which could result in privilege escalation, denial of service or
    information leaks.

    For the stable distribution (bookworm), these problems have been fixed in
    version 4.17.5+23-ga4e5191dc0-1.

    We recommend that you upgrade your xen packages.

    For the detailed security status of xen please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/xen

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xen");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2193");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2201");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31142");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31143");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45817");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45818");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45819");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/xen");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libxen-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-31143");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-31146");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxencall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxendevicemodel1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenevtchn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenforeignmemory1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxengnttab1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenhypfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenmisc4.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenstore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxentoolcore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxentoollog1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.17-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.17-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.17-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.17-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.17-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.17-armhf-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-4.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-4.17-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xenstore-utils");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'libxen-dev', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxencall1', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxendevicemodel1', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxenevtchn1', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxenforeignmemory1', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxengnttab1', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxenhypfs1', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxenmisc4.17', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxenstore4', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxentoolcore1', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'libxentoollog1', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-doc', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-hypervisor-4.17-amd64', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-hypervisor-4.17-amd64-dbg', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-hypervisor-4.17-arm64', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-hypervisor-4.17-arm64-dbg', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-hypervisor-4.17-armhf', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-hypervisor-4.17-armhf-dbg', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-hypervisor-common', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-system-amd64', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-system-arm64', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-system-armhf', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-utils-4.17', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-utils-4.17-dbg', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xen-utils-common', 'reference': '4.17.5+23-ga4e5191dc0-1'},
    {'release': '12.0', 'prefix': 'xenstore-utils', 'reference': '4.17.5+23-ga4e5191dc0-1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxen-dev / libxencall1 / libxendevicemodel1 / libxenevtchn1 / etc');
}
