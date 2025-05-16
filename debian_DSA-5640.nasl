#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5640. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192117);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-3966", "CVE-2023-5366", "CVE-2024-22563");

  script_name(english:"Debian dsa-5640 : openvswitch-common - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5640 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5640-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    March 14, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : openvswitch
    CVE ID         : CVE-2023-3966 CVE-2023-5366
    Debian Bug     : 1063492

    Two vulnerabilities were discovered in Open vSwitch, a software-based
    Ethernet virtual switch, which could result in a bypass of OpenFlow
    rules or denial of service.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 2.15.0+ds1-2+deb11u5. This update also adresses a memory leak
    tracked as CVE-2024-22563.

    For the stable distribution (bookworm), these problems have been fixed in
    version 3.1.0-2+deb12u1.

    We recommend that you upgrade your openvswitch packages.

    For the detailed security status of openvswitch please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/openvswitch

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmXy+NgACgkQEMKTtsN8
    TjasEQ//V4q2/qeHlZk+Sr/73jLvDOA7u6O+FxGGi+LHBiYIoUlD+E2jEq/pAzaK
    /hlpHCKO1g5bkf7/TcA9TaMyxo498LmT6/TX6SNB+lxOcJQlS8KyT/JtNQt31nk4
    LND1IU/WFliMdNQoqwYgZVp6innCmb2hTYcxTKeGeQndnaTRIGo/FShxgCBZHwOJ
    KB39eg0hQCDgx1DzfkA0e9u/I7Vq4MKEitV5u1H+Uf9embZaUsfwJCSaeshuxmp4
    U20r2V9hxXVYrhAeFWYGiDEY+Di4O9fDOVLw2An19ncQjDquLfRYqdys8AMxzi3+
    Vm0VasMAmZlEhdjcSjtotMI3tjgLcWGOz8BGdBUTAKK0FMtzPHLMhjfJ/cpC6jxZ
    19ZJcD3OUDIA6nf4CZjW4BOCImukqm9EUJtcQFZAGONdkelNYiz6V5R6IpbAVtLP
    Vkx5yyWWEPXau6eZKhKO0aMcBiAGUYs2LI0rmrmPBdTtQcZJmTx7U+jZiPO6Dx0Y
    P5DMwY23Z8GWPZeDX/2C8HBPqAMKfsWzIOEcXJ0HlAnVyJnC7XGBb+q4W+RFDWhc
    XYbi40SyyHrDqYBg/ne7WxEnmzfMk3F9cqRCn+owV2lbYxYRKIDZngyg2JK3sdjM
    UfnFE+5D8QRvxQQMYM9H8q3iBzR1KVEi6cpUUoTZCz6qI5rcH6E=
    =ZEHS
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openvswitch");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5366");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22563");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/openvswitch");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/openvswitch");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openvswitch-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5366");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-switch-dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-testcontroller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-openvswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'openvswitch-common', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'openvswitch-dbg', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'openvswitch-dev', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'openvswitch-ipsec', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'openvswitch-pki', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'openvswitch-switch', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'openvswitch-switch-dpdk', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'openvswitch-testcontroller', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'openvswitch-vtep', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '11.0', 'prefix': 'python3-openvswitch', 'reference': '2.15.0+ds1-2+deb11u5'},
    {'release': '12.0', 'prefix': 'openvswitch-common', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-doc', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-ipsec', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-pki', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-source', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-switch', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-switch-dpdk', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-test', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-testcontroller', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'openvswitch-vtep', 'reference': '3.1.0-2+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-openvswitch', 'reference': '3.1.0-2+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openvswitch-common / openvswitch-dbg / openvswitch-dev / etc');
}
