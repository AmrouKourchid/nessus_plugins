#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5587. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(187288);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-46218", "CVE-2023-46219");
  script_xref(name:"IAVA", value:"2023-A-0674-S");

  script_name(english:"Debian DSA-5587-1 : curl - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5587 advisory.

    Two security issues were discovered in Curl: Cookies were incorrectly validated against the public suffix
    list of domains and in some cases HSTS data could fail to save to disk. For the oldstable distribution
    (bullseye), these problems have been fixed in version 7.74.0-1.3+deb11u11. For the stable distribution
    (bookworm), these problems have been fixed in version 7.88.1-10+deb12u5. We recommend that you upgrade
    your curl packages. For the detailed security status of curl please refer to its security tracker page at:
    https://security-tracker.debian.org/tracker/curl

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/curl");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/curl");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/curl");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5587");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46219");
  script_set_attribute(attribute:"solution", value:
"Upgrade the curl packages.

For the stable distribution (bookworm), these problems have been fixed in version 7.88.1-10+deb12u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46218");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'curl', 'reference': '7.74.0-1.3+deb11u11'},
    {'release': '11.0', 'prefix': 'libcurl3-gnutls', 'reference': '7.74.0-1.3+deb11u11'},
    {'release': '11.0', 'prefix': 'libcurl3-nss', 'reference': '7.74.0-1.3+deb11u11'},
    {'release': '11.0', 'prefix': 'libcurl4', 'reference': '7.74.0-1.3+deb11u11'},
    {'release': '11.0', 'prefix': 'libcurl4-doc', 'reference': '7.74.0-1.3+deb11u11'},
    {'release': '11.0', 'prefix': 'libcurl4-gnutls-dev', 'reference': '7.74.0-1.3+deb11u11'},
    {'release': '11.0', 'prefix': 'libcurl4-nss-dev', 'reference': '7.74.0-1.3+deb11u11'},
    {'release': '11.0', 'prefix': 'libcurl4-openssl-dev', 'reference': '7.74.0-1.3+deb11u11'},
    {'release': '12.0', 'prefix': 'curl', 'reference': '7.88.1-10+deb12u5'},
    {'release': '12.0', 'prefix': 'libcurl3-gnutls', 'reference': '7.88.1-10+deb12u5'},
    {'release': '12.0', 'prefix': 'libcurl3-nss', 'reference': '7.88.1-10+deb12u5'},
    {'release': '12.0', 'prefix': 'libcurl4', 'reference': '7.88.1-10+deb12u5'},
    {'release': '12.0', 'prefix': 'libcurl4-doc', 'reference': '7.88.1-10+deb12u5'},
    {'release': '12.0', 'prefix': 'libcurl4-gnutls-dev', 'reference': '7.88.1-10+deb12u5'},
    {'release': '12.0', 'prefix': 'libcurl4-nss-dev', 'reference': '7.88.1-10+deb12u5'},
    {'release': '12.0', 'prefix': 'libcurl4-openssl-dev', 'reference': '7.88.1-10+deb12u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3-gnutls / libcurl3-nss / libcurl4 / libcurl4-doc / etc');
}
