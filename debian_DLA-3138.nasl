#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3138. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165715);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-2795", "CVE-2022-38177", "CVE-2022-38178");
  script_xref(name:"IAVA", value:"2022-A-0387-S");

  script_name(english:"Debian dla-3138 : bind9 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3138 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3138-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/               Emilio Pozuelo Monfort
    October 05, 2022                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : bind9
    Version        : 1:9.11.5.P4+dfsg-5.1+deb10u8
    CVE ID         : CVE-2022-2795 CVE-2022-38177 CVE-2022-38178

    Several vulnerabilities were discovered in BIND, a DNS server
    implementation.

    CVE-2022-2795

        Yehuda Afek, Anat Bremler-Barr and Shani Stajnrod discovered that a
        flaw in the resolver code can cause named to spend excessive amounts
        of time on processing large delegations, significantly degrade
        resolver performance and result in denial of service.

    CVE-2022-38177

        It was discovered that the DNSSEC verification code for the ECDSA
        algorithm is susceptible to a memory leak flaw. A remote attacker
        can take advantage of this flaw to cause BIND to consume resources,
        resulting in a denial of service.

    CVE-2022-38178

        It was discovered that the DNSSEC verification code for the EdDSA
        algorithm is susceptible to a memory leak flaw. A remote attacker
        can take advantage of this flaw to cause BIND to consume resources,
        resulting in a denial of service.

    For Debian 10 buster, these problems have been fixed in version
    1:9.11.5.P4+dfsg-5.1+deb10u8.

    We recommend that you upgrade your bind9 packages.

    For the detailed security status of bind9 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/bind9

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/bind9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38177");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38178");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/bind9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the bind9 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38178");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2022-2795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-export-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind9-161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns-export1104");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns1104");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libirs-export161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libirs161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc-export1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc-export161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg-export163");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg163");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwres161");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'bind9', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'bind9-doc', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'bind9-host', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'bind9utils', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'dnsutils', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libbind-dev', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libbind-export-dev', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libbind9-161', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libdns-export1104', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libdns1104', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libirs-export161', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libirs161', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libisc-export1100', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libisc1100', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libisccc-export161', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libisccc161', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libisccfg-export163', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'libisccfg163', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'},
    {'release': '10.0', 'prefix': 'liblwres161', 'reference': '1:9.11.5.P4+dfsg-5.1+deb10u8'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-doc / bind9-host / bind9utils / dnsutils / libbind-dev / etc');
}
