#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4983. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153993);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2021-20267", "CVE-2021-38598", "CVE-2021-40085");

  script_name(english:"Debian DSA-4983-1 : neutron - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4983 advisory.

    Pavel Toporkov discovered a vulnerability in Neutron, the OpenStack virtual network service, which allowed
    a reconfiguration of dnsmasq via crafted dhcp_extra_opts parameters. For the oldstable distribution
    (buster), this problem has been fixed in version 2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1. This update
    also fixes CVE-2021-20267. For the stable distribution (bullseye), this problem has been fixed in version
    2:17.2.1-0+deb11u1. This update also fixes CVE-2021-38598. We recommend that you upgrade your neutron
    packages. For the detailed security status of neutron please refer to its security tracker page at:
    https://security-tracker.debian.org/tracker/neutron

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=993398");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/neutron");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4983");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20267");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40085");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/neutron");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/neutron");
  script_set_attribute(attribute:"solution", value:
"Upgrade the neutron packages.

For the stable distribution (bullseye), this problem has been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38598");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-dhcp-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-l3-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-linuxbridge-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-macvtap-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-metadata-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-metering-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-openvswitch-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-ovn-metadata-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-plugin-nec-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-rpc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron-sriov-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-neutron");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'neutron-api', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-common', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-dhcp-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-doc', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-l3-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-linuxbridge-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-macvtap-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-metadata-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-metering-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-openvswitch-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-ovn-metadata-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-plugin-nec-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-rpc-server', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-server', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'neutron-sriov-agent', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-neutron', 'reference': '2:13.0.7+git.2021.09.27.bace3d1890-0+deb10u1'},
    {'release': '11.0', 'prefix': 'neutron-api', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-common', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-dhcp-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-doc', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-l3-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-linuxbridge-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-macvtap-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-metadata-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-metering-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-openvswitch-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-ovn-metadata-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-plugin-nec-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-rpc-server', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-server', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'neutron-sriov-agent', 'reference': '2:17.2.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-neutron', 'reference': '2:17.2.1-0+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'neutron-api / neutron-common / neutron-dhcp-agent / neutron-doc / etc');
}
