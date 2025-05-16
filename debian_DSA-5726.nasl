#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5726. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(201931);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2024-37370", "CVE-2024-37371");
  script_xref(name:"IAVB", value:"2024-B-0082");

  script_name(english:"Debian dsa-5726 : krb5-admin-server - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5726 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5726-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    July 05, 2024                         https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : krb5
    CVE ID         : CVE-2024-37370 CVE-2024-37371

    Two vulnerabilities were discovered in the GSS message token handling in
    krb5, the MIT implementation of Kerberos. An attacker can take advantage
    of these flaws to bypass integrity protections or cause a denial of
    service.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 1.18.3-6+deb11u5.

    For the stable distribution (bookworm), these problems have been fixed in
    version 1.20.1-2+deb12u2.

    We recommend that you upgrade your krb5 packages.

    For the detailed security status of krb5 please refer to its security
    tracker page at:
    https://security-tracker.debian.org/tracker/krb5

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/krb5");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-37370");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-37371");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/krb5");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/krb5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the krb5-admin-server packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37371");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-gss-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-k5tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kpropd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5clnt-mit12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5srv-mit12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdb5-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrad0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'krb5-admin-server', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-doc', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-gss-samples', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-k5tls', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-kdc', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-kdc-ldap', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-kpropd', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-locales', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-multidev', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-otp', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-pkinit', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'krb5-user', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libgssapi-krb5-2', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libgssrpc4', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libk5crypto3', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkadm5clnt-mit12', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkadm5srv-mit12', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkdb5-10', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkrad-dev', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkrad0', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkrb5-3', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkrb5-dbg', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkrb5-dev', 'reference': '1.18.3-6+deb11u5'},
    {'release': '11.0', 'prefix': 'libkrb5support0', 'reference': '1.18.3-6+deb11u5'},
    {'release': '12.0', 'prefix': 'krb5-admin-server', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-doc', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-gss-samples', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-k5tls', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-kdc', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-kdc-ldap', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-kpropd', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-locales', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-multidev', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-otp', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-pkinit', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'krb5-user', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libgssapi-krb5-2', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libgssrpc4', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libk5crypto3', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkadm5clnt-mit12', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkadm5srv-mit12', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkdb5-10', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkrad-dev', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkrad0', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkrb5-3', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkrb5-dbg', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkrb5-dev', 'reference': '1.20.1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkrb5support0', 'reference': '1.20.1-2+deb12u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-admin-server / krb5-doc / krb5-gss-samples / krb5-k5tls / etc');
}
