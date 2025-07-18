#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5251. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165757);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2022-2928", "CVE-2022-2929");
  script_xref(name:"IAVB", value:"2022-B-0037");

  script_name(english:"Debian DSA-5251-1 : isc-dhcp - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5251 advisory.

    Several vulnerabilities have been discovered in the ISC DHCP client, relay and server. CVE-2022-2928 It
    was discovered that the DHCP server does not correctly perform option reference counting when configured
    with allow leasequery;. A remote attacker can take advantage of this flaw to cause a denial of service
    (daemon crash). CVE-2022-2929 It was discovered that the DHCP server is prone to a memory leak flaw when
    handling contents of option 81 (fqdn) data received in a DHCP packet. A remote attacker can take advantage
    of this flaw to cause DHCP servers to consume resources, resulting in denial of service. For the stable
    distribution (bullseye), these problems have been fixed in version 4.4.1-2.3+deb11u1. We recommend that
    you upgrade your isc-dhcp packages. For the detailed security status of isc-dhcp please refer to its
    security tracker page at: https://security-tracker.debian.org/tracker/isc-dhcp

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1021320");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/isc-dhcp");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5251");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2928");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2929");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/isc-dhcp");
  script_set_attribute(attribute:"solution", value:
"Upgrade the isc-dhcp packages.

For the stable distribution (bullseye), these problems have been fixed in version 4.4.1-2.3+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-ddns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp-server-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'isc-dhcp-client', 'reference': '4.4.1-2.3+deb11u1'},
    {'release': '11.0', 'prefix': 'isc-dhcp-client-ddns', 'reference': '4.4.1-2.3+deb11u1'},
    {'release': '11.0', 'prefix': 'isc-dhcp-client-udeb', 'reference': '4.4.1-2.3+deb11u1'},
    {'release': '11.0', 'prefix': 'isc-dhcp-common', 'reference': '4.4.1-2.3+deb11u1'},
    {'release': '11.0', 'prefix': 'isc-dhcp-dev', 'reference': '4.4.1-2.3+deb11u1'},
    {'release': '11.0', 'prefix': 'isc-dhcp-relay', 'reference': '4.4.1-2.3+deb11u1'},
    {'release': '11.0', 'prefix': 'isc-dhcp-server', 'reference': '4.4.1-2.3+deb11u1'},
    {'release': '11.0', 'prefix': 'isc-dhcp-server-ldap', 'reference': '4.4.1-2.3+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'isc-dhcp-client / isc-dhcp-client-ddns / isc-dhcp-client-udeb / etc');
}
