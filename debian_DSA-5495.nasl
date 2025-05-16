#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5495. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181250);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/11");

  script_cve_id(
    "CVE-2022-36440",
    "CVE-2022-40302",
    "CVE-2022-40318",
    "CVE-2022-43681",
    "CVE-2023-31490",
    "CVE-2023-38802",
    "CVE-2023-41358"
  );

  script_name(english:"Debian DSA-5495-1 : frr - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5495 advisory.

  - A reachable assertion was found in Frrouting frr-bgpd 8.3.0 in the peek_for_as4_capability function.
    Attackers can maliciously construct BGP open packets and send them to BGP peers running frr-bgpd,
    resulting in DoS. (CVE-2022-36440)

  - An issue was discovered in bgpd in FRRouting (FRR) through 8.4. By crafting a BGP OPEN message with an
    option of type 0xff (Extended Length from RFC 9072), attackers may cause a denial of service (assertion
    failure and daemon restart, or out-of-bounds read). This is possible because of inconsistent boundary
    checks that do not account for reading 3 bytes (instead of 2) in this 0xff case. (CVE-2022-40302)

  - An issue was discovered in bgpd in FRRouting (FRR) through 8.4. By crafting a BGP OPEN message with an
    option of type 0xff (Extended Length from RFC 9072), attackers may cause a denial of service (assertion
    failure and daemon restart, or out-of-bounds read). This is possible because of inconsistent boundary
    checks that do not account for reading 3 bytes (instead of 2) in this 0xff case. NOTE: this behavior
    occurs in bgp_open_option_parse in the bgp_open.c file, a different location (with a different attack
    vector) relative to CVE-2022-40302. (CVE-2022-40318)

  - An out-of-bounds read exists in the BGP daemon of FRRouting FRR through 8.4. When sending a malformed BGP
    OPEN message that ends with the option length octet (or the option length word, in case of an extended
    OPEN message), the FRR code reads of out of the bounds of the packet, throwing a SIGABRT signal and
    exiting. This results in a bgpd daemon restart, causing a Denial-of-Service condition. (CVE-2022-43681)

  - An issue found in Frrouting bgpd v.8.4.2 allows a remote attacker to cause a denial of service via the
    bgp_attr_psid_sub() function. (CVE-2023-31490)

  - FRRouting FRR 7.5.1 through 9.0 and Pica8 PICOS 4.3.3.2 allow a remote attacker to cause a denial of
    service via a crafted BGP update with a corrupted attribute 23 (Tunnel Encapsulation). (CVE-2023-38802)

  - An issue was discovered in FRRouting FRR through 9.0. bgpd/bgp_packet.c processes NLRIs if the attribute
    length is zero. (CVE-2023-41358)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1035829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/frr");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5495");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36440");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40302");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40318");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43681");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31490");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-41358");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/frr");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/frr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the frr packages.

For the stable distribution (bookworm), these problems have been fixed in version 8.4.4-1.1~deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41358");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-pythontools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-rpki-rtrlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'frr', 'reference': '7.5.1-1.1+deb11u2'},
    {'release': '11.0', 'prefix': 'frr-doc', 'reference': '7.5.1-1.1+deb11u2'},
    {'release': '11.0', 'prefix': 'frr-pythontools', 'reference': '7.5.1-1.1+deb11u2'},
    {'release': '11.0', 'prefix': 'frr-rpki-rtrlib', 'reference': '7.5.1-1.1+deb11u2'},
    {'release': '11.0', 'prefix': 'frr-snmp', 'reference': '7.5.1-1.1+deb11u2'},
    {'release': '12.0', 'prefix': 'frr', 'reference': '8.4.4-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'frr-doc', 'reference': '8.4.4-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'frr-pythontools', 'reference': '8.4.4-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'frr-rpki-rtrlib', 'reference': '8.4.4-1.1~deb12u1'},
    {'release': '12.0', 'prefix': 'frr-snmp', 'reference': '8.4.4-1.1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'frr / frr-doc / frr-pythontools / frr-rpki-rtrlib / frr-snmp');
}
