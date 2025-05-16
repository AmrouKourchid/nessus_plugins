#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5504. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181817);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-3341", "CVE-2023-4236");
  script_xref(name:"IAVA", value:"2023-A-0500-S");

  script_name(english:"Debian DSA-5504-1 : bind9 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5504 advisory.

    Several vulnerabilities were discovered in BIND, a DNS server implementation. CVE-2023-3341 A stack
    exhaustion flaw was discovered in the control channel code which may result in denial of service (named
    daemon crash). CVE-2023-4236 Robert Story discovered that a flaw in the networking code handling DNS-over-
    TLS queries could cause named to terminate unexpectedly due to an assertion failure, resulting in denial
    of service when under high DNS-over-TLS query load conditions. For the oldstable distribution (bullseye),
    these problems have been fixed in version 1:9.16.44-1~deb11u1. The oldstable distribution (bullseye) is
    only affected by CVE-2023-3341. For the stable distribution (bookworm), these problems have been fixed in
    version 1:9.18.19-1~deb12u1. We recommend that you upgrade your bind9 packages. For the detailed security
    status of bind9 please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/bind9

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1052416");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/bind9");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5504");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3341");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4236");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/bind9");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/bind9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the bind9 packages.

For the stable distribution (bookworm), these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4236");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
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
    {'release': '11.0', 'prefix': 'bind9', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-dev', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-dnsutils', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-doc', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-host', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-libs', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9-utils', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '11.0', 'prefix': 'bind9utils', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '11.0', 'prefix': 'dnsutils', 'reference': '1:9.16.44-1~deb11u1'},
    {'release': '12.0', 'prefix': 'bind9', 'reference': '1:9.18.19-1~deb12u1'},
    {'release': '12.0', 'prefix': 'bind9-dev', 'reference': '1:9.18.19-1~deb12u1'},
    {'release': '12.0', 'prefix': 'bind9-dnsutils', 'reference': '1:9.18.19-1~deb12u1'},
    {'release': '12.0', 'prefix': 'bind9-doc', 'reference': '1:9.18.19-1~deb12u1'},
    {'release': '12.0', 'prefix': 'bind9-host', 'reference': '1:9.18.19-1~deb12u1'},
    {'release': '12.0', 'prefix': 'bind9-libs', 'reference': '1:9.18.19-1~deb12u1'},
    {'release': '12.0', 'prefix': 'bind9-utils', 'reference': '1:9.18.19-1~deb12u1'},
    {'release': '12.0', 'prefix': 'bind9utils', 'reference': '1:9.18.19-1~deb12u1'},
    {'release': '12.0', 'prefix': 'dnsutils', 'reference': '1:9.18.19-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-dev / bind9-dnsutils / bind9-doc / bind9-host / etc');
}
