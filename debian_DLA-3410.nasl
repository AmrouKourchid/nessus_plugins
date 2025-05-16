#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3410. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174966);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-1668");

  script_name(english:"Debian dla-3410 : openvswitch-common - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3410
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3410-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    May 01, 2023                                  https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : openvswitch
    Version        : 2.10.7+ds1-0+deb10u4
    CVE ID         : CVE-2023-1668
    Debian Bug     : 1034042

    David Marchand discovered that Open vSwitch, a multilayer, software-based,
    Ethernet virtual switch, was vulnerable to crafted IP packets with ip proto
    set to 0, potentially causing a denial of service.

    Triggering the vulnerability requires an attacker to send a crafted IP
    packet with protocol field set to 0 and the flow rules to contain 'set'
    actions on other fields in the IP protocol header.  The resulting flows will
    omit required actions, and fail to mask the IP protocol field, resulting in
    a large bucket which captures all IP packets.

    For Debian 10 buster, this problem has been fixed in version
    2.10.7+ds1-0+deb10u4.

    We recommend that you upgrade your openvswitch packages.

    For the detailed security status of openvswitch please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/openvswitch

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openvswitch");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1668");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/openvswitch");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openvswitch-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1668");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-testcontroller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovn-controller-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-openvswitch");
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
    {'release': '10.0', 'prefix': 'openvswitch-common', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'openvswitch-dbg', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'openvswitch-dev', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'openvswitch-pki', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'openvswitch-switch', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'openvswitch-testcontroller', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'openvswitch-vtep', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'ovn-central', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'ovn-controller-vtep', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'ovn-host', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'python-openvswitch', 'reference': '2.10.7+ds1-0+deb10u4'},
    {'release': '10.0', 'prefix': 'python3-openvswitch', 'reference': '2.10.7+ds1-0+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openvswitch-common / openvswitch-dbg / openvswitch-dev / etc');
}
