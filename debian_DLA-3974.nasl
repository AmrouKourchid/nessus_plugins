#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3974. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211973);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/30");

  script_cve_id(
    "CVE-2022-0934",
    "CVE-2023-28450",
    "CVE-2023-50387",
    "CVE-2023-50868"
  );

  script_name(english:"Debian dla-3974 : dnsmasq - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3974 advisory.

    -lts-announce@lists.debian.org
    Subject: [SECURITY] [DLA 3974-1] dnsmasq security update

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3974-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Lee Garrett
    November 29, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : dnsmasq
    Version        : 2.85-1+deb11u1
    CVE ID         : CVE-2022-0934 CVE-2023-28450 CVE-2023-50387 CVE-2023-50868
    Debian Bug     :

    Brief introduction

    CVE-2022-0934

        A single-byte, non-arbitrary write/use-after-free flaw was found in dnsmasq.
        This flaw allows an attacker who sends a crafted packet processed by
        dnsmasq, potentially causing a denial of service.

    CVE-2023-28450

        An issue was discovered in Dnsmasq before 2.90. The default maximum EDNS.0
        UDP packet size was set to 4096 but should be 1232 because of DNS Flag Day
        2020.

    CVE-2023-50387

        Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840,
        and related RFCs) allow remote attackers to cause a denial of service (CPU
        consumption) via one or more DNSSEC responses, aka the KeyTrap issue. One
        of the concerns is that, when there is a zone with many DNSKEY and RRSIG
        records, the protocol specification implies that an algorithm must evaluate
        all combinations of DNSKEY and RRSIG records.

    CVE-2023-50868

        The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC
        9276 guidance is skipped) allows remote attackers to cause a denial of
        service (CPU consumption for SHA-1 computations) via DNSSEC responses in a
        random subdomain attack, aka the NSEC3 issue. The RFC 5155 specification
        implies that an algorithm must perform thousands of iterations of a hash
        function in certain situations.

    For Debian 11 bullseye, these problems have been fixed in version
    2.85-1+deb11u1.

    We recommend that you upgrade your dnsmasq packages.

    For the detailed security status of dnsmasq please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/dnsmasq

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dnsmasq");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28450");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50387");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50868");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/dnsmasq");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dnsmasq packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50387");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsmasq-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsmasq-base-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsmasq-utils");
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
    {'release': '11.0', 'prefix': 'dnsmasq', 'reference': '2.85-1+deb11u1'},
    {'release': '11.0', 'prefix': 'dnsmasq-base', 'reference': '2.85-1+deb11u1'},
    {'release': '11.0', 'prefix': 'dnsmasq-base-lua', 'reference': '2.85-1+deb11u1'},
    {'release': '11.0', 'prefix': 'dnsmasq-utils', 'reference': '2.85-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnsmasq / dnsmasq-base / dnsmasq-base-lua / dnsmasq-utils');
}
