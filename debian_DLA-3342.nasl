#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3342. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171904);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-41859", "CVE-2022-41860", "CVE-2022-41861");

  script_name(english:"Debian dla-3342 : freeradius - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3342 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3342-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    February 24, 2023                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : freeradius
    Version        : 3.0.17+dfsg-1.1+deb10u2
    CVE ID         : CVE-2022-41859 CVE-2022-41860 CVE-2022-41861

    Several flaws were found in freeradius, a high-performance and highly
    configurable RADIUS server.

    CVE-2022-41859

        In freeradius, the EAP-PWD function compute_password_element() leaks
        information about the password which allows an attacker to substantially
        reduce the size of an offline dictionary attack.

    CVE-2022-41860

        In freeradius, when an EAP-SIM supplicant sends an unknown SIM option, the
        server will try to look that option up in the internal dictionaries. This
        lookup will fail, but the SIM code will not check for that failure.
        Instead, it will dereference a NULL pointer, and cause the server to crash.

    CVE-2022-41861

        A malicious RADIUS client or home server can send a malformed attribute
        which can cause the server to crash.

    For Debian 10 buster, these problems have been fixed in version
    3.0.17+dfsg-1.1+deb10u2.

    We recommend that you upgrade your freeradius packages.

    For the detailed security status of freeradius please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/freeradius

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/freeradius");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41860");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41861");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/freeradius");
  script_set_attribute(attribute:"solution", value:
"Upgrade the freeradius packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-iodbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-memcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freeradius-yubikey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreeradius-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreeradius3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'freeradius', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-common', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-config', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-dhcp', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-iodbc', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-krb5', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-ldap', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-memcached', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-mysql', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-postgresql', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-python2', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-redis', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-rest', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-utils', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'freeradius-yubikey', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libfreeradius-dev', 'reference': '3.0.17+dfsg-1.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libfreeradius3', 'reference': '3.0.17+dfsg-1.1+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freeradius / freeradius-common / freeradius-config / freeradius-dhcp / etc');
}
