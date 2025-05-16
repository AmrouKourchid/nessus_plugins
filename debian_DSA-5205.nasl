#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5205. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164092);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2022-2031",
    "CVE-2022-32742",
    "CVE-2022-32744",
    "CVE-2022-32745",
    "CVE-2022-32746"
  );
  script_xref(name:"IAVA", value:"2022-A-0299-S");

  script_name(english:"Debian DSA-5205-1 : samba - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5205 advisory.

    Several vulnerabilities have been discovered in Samba, a SMB/CIFS file, print, and login server for Unix.
    CVE-2022-2031 Luke Howard reported that Samba AD users can bypass certain restrictions associated with
    changing passwords. A user who has been requested to change their password can exploit this to obtain and
    use tickets to other services. CVE-2022-32742 Luca Moro reported that a SMB1 client with write access to a
    share can cause server memory content to be leaked. CVE-2022-32744 Joseph Sutton reported that Samba AD
    users can forge password change requests for any user, resulting in privilege escalation. CVE-2022-32745
    Joseph Sutton reported that Samba AD users can crash the server process with a specially crafted LDAP add
    or modify request. CVE-2022-32746 Joseph Sutton and Andrew Bartlett reported that Samba AD users can cause
    a use-after-free in the server process with a specially crafted LDAP add or modify request. For the stable
    distribution (bullseye), these problems have been fixed in version 2:4.13.13+dfsg-1~deb11u5. The fix for
    CVE-2022-32745 required an update to ldb 2:2.2.3-2~deb11u2 to correct the defect. We recommend that you
    upgrade your samba packages. For the detailed security status of samba please refer to its security
    tracker page at: https://security-tracker.debian.org/tracker/samba

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1016449");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/samba");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5205");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32742");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32746");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/samba");
  script_set_attribute(attribute:"solution", value:
"Upgrade the samba packages.

For the stable distribution (bullseye), these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32745");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32744");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:registry-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-vfs-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winbind");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ctdb', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'libnss-winbind', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'libpam-winbind', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'libsmbclient', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'libsmbclient-dev', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'libwbclient-dev', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'libwbclient0', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'python3-samba', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'registry-tools', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'samba', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'samba-common', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'samba-common-bin', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'samba-dev', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'samba-dsdb-modules', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'samba-libs', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'samba-testsuite', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'samba-vfs-modules', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'smbclient', 'reference': '2:4.13.13+dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'winbind', 'reference': '2:4.13.13+dfsg-1~deb11u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-winbind / libsmbclient / etc');
}
