#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5560. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(186027);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-41913");

  script_name(english:"Debian DSA-5560-1 : strongswan - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5560
advisory.

    Florian Picca reported a bug in the charon-tkm daemon in strongSwan an IKE/IPsec suite. The TKM-backed
    version of the charon IKE daemon (charon-tkm) doesn't check the length of received Diffie-Hellman public
    values before copying them to a fixed-size buffer on the stack, causing a buffer overflow that could
    potentially be exploited for remote code execution by sending a specially crafted and unauthenticated
    IKE_SA_INIT message. For the oldstable distribution (bullseye), this problem has been fixed in version
    5.9.1-1+deb11u4. For the stable distribution (bookworm), this problem has been fixed in version
    5.9.8-5+deb12u1. We recommend that you upgrade your strongswan packages. For the detailed security status
    of strongswan please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/strongswan

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/strongswan");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5560");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-41913");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/strongswan");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/strongswan");
  script_set_attribute(attribute:"solution", value:
"Upgrade the strongswan packages.

For the stable distribution (bookworm), this problem has been fixed in version 5.9.8-5+deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:charon-cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:charon-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcharon-extauth-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcharon-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan-standard-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-charon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-libcharon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-scepclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-starter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-swanctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'charon-cmd', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'charon-systemd', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'libcharon-extauth-plugins', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'libcharon-extra-plugins', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'libstrongswan', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'libstrongswan-extra-plugins', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'libstrongswan-standard-plugins', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'strongswan', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'strongswan-charon', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'strongswan-libcharon', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'strongswan-nm', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'strongswan-pki', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'strongswan-scepclient', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'strongswan-starter', 'reference': '5.9.1-1+deb11u4'},
    {'release': '11.0', 'prefix': 'strongswan-swanctl', 'reference': '5.9.1-1+deb11u4'},
    {'release': '12.0', 'prefix': 'charon-cmd', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'charon-systemd', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libcharon-extauth-plugins', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libcharon-extra-plugins', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libstrongswan', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libstrongswan-extra-plugins', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'libstrongswan-standard-plugins', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'strongswan', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'strongswan-charon', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'strongswan-libcharon', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'strongswan-nm', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'strongswan-pki', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'strongswan-starter', 'reference': '5.9.8-5+deb12u1'},
    {'release': '12.0', 'prefix': 'strongswan-swanctl', 'reference': '5.9.8-5+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'charon-cmd / charon-systemd / libcharon-extauth-plugins / etc');
}
