#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3794. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(193899);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2019-17069",
    "CVE-2020-14002",
    "CVE-2021-36367",
    "CVE-2023-48795"
  );

  script_name(english:"Debian dla-3794 : pterm - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3794 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3794-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    April 25, 2024                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : putty
    Version        : 0.74-1+deb11u1~deb10u1
    CVE ID         : CVE-2019-17069 CVE-2020-14002 CVE-2021-36367 CVE-2023-48795
    Debian Bug     : 990901

    Putty, a Telnet/SSH client for X, was vulnerable.

    CVE-2019-17069

      PuTTY allowed remote SSH-1 servers to cause a denial
      of service by accessing freed memory locations via an
      SSH1_MSG_DISCONNECT message.

    CVE-2020-14002

      PuTTY had an Observable Discrepancy leading to an
      information leak in the algorithm negotiation.
      This allowed man-in-the-middle attackers to target
      initial connection attempts (where no host key for the
      server has been cached by the client).

    CVE-2021-36367

      PuTTY proceeded with establishing an SSH session even
      if it has never sent a substantive authentication response.
      This made it easier for an attacker-controlled SSH server
      to present a later spoofed authentication prompt (that the
      attacker can use to capture credential data, and use that
      data for purposes that are undesired by the client user).

    CVE-2023-48795

       PuTTY was vulnerable to Terrapin attack.  The SSH transport
       protocol with certain OpenSSH extensions, allowed remote attackers
       to bypass integrity checks such that some packets are omitted (from
       the extension negotiation message), and a client and server may
       consequently end up with a connection for which some security
       features have been downgraded or disabled. This occurs because the
       SSH Binary Packet Protocol (BPP), implemented by these extensions,
       mishandles the handshake phase and mishandles use of sequence
       numbers. For example, there is an effective attack against SSH's
       use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The
       bypass occurs in chacha20-poly1305 and (if CBC is used)
       the -etm MAC algorithms.

    For Debian 10 buster, this problem has been fixed in version
    0.74-1+deb11u1~deb10u1.

    We recommend that you upgrade your putty packages.

    For the detailed security status of putty please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/putty

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/putty");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-17069");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-14002");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36367");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-48795");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/putty");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pterm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36367");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty-tools");
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
    {'release': '10.0', 'prefix': 'pterm', 'reference': '0.74-1+deb11u1~deb10u1'},
    {'release': '10.0', 'prefix': 'putty', 'reference': '0.74-1+deb11u1~deb10u1'},
    {'release': '10.0', 'prefix': 'putty-doc', 'reference': '0.74-1+deb11u1~deb10u1'},
    {'release': '10.0', 'prefix': 'putty-tools', 'reference': '0.74-1+deb11u1~deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pterm / putty / putty-doc / putty-tools');
}
