#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3797. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(194417);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-26125",
    "CVE-2022-26126",
    "CVE-2022-26127",
    "CVE-2022-26128",
    "CVE-2022-26129",
    "CVE-2022-37035",
    "CVE-2023-38406",
    "CVE-2023-38407",
    "CVE-2023-46752",
    "CVE-2023-46753",
    "CVE-2023-47234",
    "CVE-2023-47235",
    "CVE-2024-31948",
    "CVE-2024-31949"
  );

  script_name(english:"Debian dla-3797 : frr - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3797 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3797-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    April 28, 2024                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : frr
    Version        : 7.5.1-1.1+deb10u2
    CVE ID         : CVE-2022-26125 CVE-2022-26126 CVE-2022-26127 CVE-2022-26128
                     CVE-2022-26129 CVE-2022-37035 CVE-2023-38406 CVE-2023-38407
                     CVE-2023-46752 CVE-2023-46753 CVE-2023-47234 CVE-2023-47235
                     CVE-2024-31948 CVE-2024-31949
    Debian Bug     : 1008010 1016978 1055852

    Several vulnerabilities have been found in frr, the FRRouting suite of
    internet protocols. An attacker could craft packages to trigger buffer
    overflows with the possibility to gain remote code execution, buffer
    overreads, crashes or trick the software to enter an infinite loop.

    CVE-2022-26125

        Buffer overflow vulnerabilities exist in FRRouting through 8.1.0 due to
        wrong checks on the input packet length in isisd/isis_tlvs.c.

    CVE-2022-26126

        Buffer overflow vulnerabilities exist in FRRouting through 8.1.0 due to
        the use of strdup with a non-zero-terminated binary string in
        isis_nb_notifications.c.

    CVE-2022-26127

        A buffer overflow vulnerability exists in FRRouting through 8.1.0 due to
        missing a check on the input packet length in the babel_packet_examin
        function in babeld/message.c.

    CVE-2022-26128

        A buffer overflow vulnerability exists in FRRouting through 8.1.0 due to
        a wrong check on the input packet length in the babel_packet_examin
        function in babeld/message.c.

    CVE-2022-26129

        Buffer overflow vulnerabilities exist in FRRouting through 8.1.0 due to
        wrong checks on the subtlv length in the functions, parse_hello_subtlv,
        parse_ihu_subtlv, and parse_update_subtlv in babeld/message.c.

    CVE-2022-37035

        An issue was discovered in bgpd in FRRouting (FRR) 8.3. In
        bgp_notify_send_with_data() and bgp_process_packet() in bgp_packet.c,
        there is a possible use-after-free due to a race condition. This could
        lead to Remote Code Execution or Information Disclosure by sending
        crafted BGP packets. User interaction is not needed for exploitation.

    CVE-2023-38406

        bgpd/bgp_flowspec.c in FRRouting (FRR) before 8.4.3 mishandles an nlri
        length of zero, aka a flowspec overflow.

    CVE-2023-38407

        bgpd/bgp_label.c in FRRouting (FRR) before 8.5 attempts to read beyond
        the end of the stream during labeled unicast parsing.

    CVE-2023-46752

        An issue was discovered in FRRouting FRR through 9.0.1. It mishandles
        malformed MP_REACH_NLRI data, leading to a crash.

    CVE-2023-46753

        An issue was discovered in FRRouting FRR through 9.0.1. A crash can
        occur for a crafted BGP UPDATE message without mandatory attributes,
        e.g., one with only an unknown transit attribute.

    CVE-2023-47234

        An issue was discovered in bgpd in FRRouting (FRR) 8.3. In
        bgp_notify_send_with_data() and bgp_process_packet() in bgp_packet.c,
        there is a possible use-after-free due to a race condition. This could
        lead to Remote Code Execution or Information Disclosure by sending
        crafted BGP packets. User interaction is not needed for exploitation.

    CVE-2023-47235

        An issue was discovered in FRRouting FRR through 9.0.1. A crash can
        occur when a malformed BGP UPDATE message with an EOR is processed,
        because the presence of EOR does not lead to a treat-as-withdraw
        outcome.

    CVE-2024-31948

        In FRRouting (FRR) through 9.1, an attacker using a malformed Prefix SID
        attribute in a BGP UPDATE packet can cause the bgpd daemon to crash.

    CVE-2024-31949

        In FRRouting (FRR) through 9.1, an infinite loop can occur when
        receiving a MP/GR capability as a dynamic capability because malformed
        data results in a pointer not advancing.

    For Debian 10 buster, these problems have been fixed in version
    7.5.1-1.1+deb10u2.

    We recommend that you upgrade your frr packages.

    For the detailed security status of frr please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/frr

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/frr");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26126");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26127");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26128");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26129");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37035");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38406");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38407");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-47234");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-47235");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31948");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31949");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/frr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the frr packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26129");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38406");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-pythontools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-rpki-rtrlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'frr', 'reference': '7.5.1-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'frr-doc', 'reference': '7.5.1-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'frr-pythontools', 'reference': '7.5.1-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'frr-rpki-rtrlib', 'reference': '7.5.1-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'frr-snmp', 'reference': '7.5.1-1.1+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'frr / frr-doc / frr-pythontools / frr-rpki-rtrlib / frr-snmp');
}
