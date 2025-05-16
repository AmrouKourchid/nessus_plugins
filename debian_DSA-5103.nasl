#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5103. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158979);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2021-4160", "CVE-2022-0778");
  script_xref(name:"IAVA", value:"2021-A-0602-S");

  script_name(english:"Debian DSA-5103-1 : openssl - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5103 advisory.

    Tavis Ormandy discovered that the BN_mod_sqrt() function of OpenSSL could be tricked into an infinite
    loop. This could result in denial of service via malformed certificates. Additional details can be found
    in the upstream advisory: https://www.openssl.org/news/secadv/20220315.txt In addition this update
    corrects a carry propagation bug specific to MIPS architectures. For the oldstable distribution (buster),
    this problem has been fixed in version 1.1.1d-0+deb10u8. For the stable distribution (bullseye), this
    problem has been fixed in version 1.1.1k-1+deb11u2. We recommend that you upgrade your openssl packages.
    For the detailed security status of openssl please refer to its security tracker page at:
    https://security-tracker.debian.org/tracker/openssl

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=989604");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openssl");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5103");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4160");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0778");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/openssl");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/openssl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openssl packages.

For the stable distribution (bullseye), this problem has been fixed in version 1.1.1k-1+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrypto1.1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.1-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libcrypto1.1-udeb', 'reference': '1.1.1d-0+deb10u8'},
    {'release': '10.0', 'prefix': 'libssl-dev', 'reference': '1.1.1d-0+deb10u8'},
    {'release': '10.0', 'prefix': 'libssl-doc', 'reference': '1.1.1d-0+deb10u8'},
    {'release': '10.0', 'prefix': 'libssl1.1', 'reference': '1.1.1d-0+deb10u8'},
    {'release': '10.0', 'prefix': 'libssl1.1-udeb', 'reference': '1.1.1d-0+deb10u8'},
    {'release': '10.0', 'prefix': 'openssl', 'reference': '1.1.1d-0+deb10u8'},
    {'release': '11.0', 'prefix': 'libcrypto1.1-udeb', 'reference': '1.1.1k-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libssl-dev', 'reference': '1.1.1k-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libssl-doc', 'reference': '1.1.1k-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libssl1.1', 'reference': '1.1.1k-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libssl1.1-udeb', 'reference': '1.1.1k-1+deb11u2'},
    {'release': '11.0', 'prefix': 'openssl', 'reference': '1.1.1k-1+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcrypto1.1-udeb / libssl-dev / libssl-doc / libssl1.1 / etc');
}
