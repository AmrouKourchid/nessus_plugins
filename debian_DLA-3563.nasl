#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3563. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181444);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2016-2124",
    "CVE-2019-10218",
    "CVE-2019-14833",
    "CVE-2019-14847",
    "CVE-2019-14902",
    "CVE-2019-14907",
    "CVE-2019-19344"
  );
  script_xref(name:"IAVA", value:"2019-A-0407-S");
  script_xref(name:"IAVA", value:"2020-A-0035-S");

  script_name(english:"Debian dla-3563 : ctdb - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3563 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3563-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Lee Garrett
    September 12, 2023                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : samba
    Version        : 2:4.9.5+dfsg-5+deb10u4
    CVE ID         : CVE-2016-2124 CVE-2019-10218 CVE-2019-14833 CVE-2019-14847
                     CVE-2019-14902 CVE-2019-14907 CVE-2019-19344
    Debian Bug     :

    Several vulnerabilities were discovered in Samba, the SMB/CIFS file, print, and
    login server for Unix.

    CVE-2016-2124

        A flaw was found in the way samba implemented SMB1 authentication. An
        attacker could use this flaw to retrieve the plaintext password sent over
        the wire even if Kerberos authentication was required.

    CVE-2019-10218

        A flaw was found in the samba client, all samba versions before samba
        4.11.2, 4.10.10 and 4.9.15, where a malicious server can supply a pathname
        to the client with separators. This could allow the client to access files
        and folders outside of the SMB network pathnames. An attacker could use this
        vulnerability to create files outside of the current working directory using
        the privileges of the client user.

    CVE-2019-14833

        A flaw was found in Samba, all versions starting samba 4.5.0 before samba
        4.9.15, samba 4.10.10, samba 4.11.2, in the way it handles a user password
        change or a new password for a samba user. The Samba Active Directory Domain
        Controller can be configured to use a custom script to check for password
        complexity. This configuration can fail to verify password complexity when
        non-ASCII characters are used in the password, which could lead to weak
        passwords being set for samba users, making it vulnerable to dictionary
        attacks.

    CVE-2019-14847

        A flaw was found in samba 4.0.0 before samba 4.9.15 and samba 4.10.x before
        4.10.10. An attacker can crash AD DC LDAP server via dirsync resulting in
        denial of service. Privilege escalation is not possible with this issue.

    CVE-2019-14902

        There is an issue in all samba 4.11.x versions before 4.11.5, all samba
        4.10.x versions before 4.10.12 and all samba 4.9.x versions before 4.9.18,
        where the removal of the right to create or modify a subtree would not
        automatically be taken away on all domain controllers.

    CVE-2019-14907

        All samba versions 4.9.x before 4.9.18, 4.10.x before 4.10.12 and 4.11.x
        before 4.11.5 have an issue where if it is set with log level = 3 (or
        above) then the string obtained from the client, after a failed character
        conversion, is printed. Such strings can be provided during the NTLMSSP
        authentication exchange. In the Samba AD DC in particular, this may cause a
        long-lived process(such as the RPC server) to terminate. (In the file server
        case, the most likely target, smbd, operates as process-per-client and so a
        crash there is harmless).

    CVE-2019-19344

        There is a use-after-free issue in all samba 4.9.x versions before 4.9.18,
        all samba 4.10.x versions before 4.10.12 and all samba 4.11.x versions
        before 4.11.5, essentially due to a call to realloc() while other local
        variables still point at the original buffer.

    For Debian 10 buster, these problems have been fixed in version
    2:4.9.5+dfsg-5+deb10u4.

    We recommend that you upgrade your samba packages.

    Admins of AD DC setups are reminded and strongly encouraged to upgrade to
    bullseye and then bookworm, as AD DC setups are unsupported in buster since [DSA
    5015-1], and in bullseye since [DSA 5477-1].

    [DSA 5015-1] https://www.debian.org/security/2021/dsa-5015
    [DSA 5477-1] https://www.debian.org/security/2023/dsa-5477


    For the detailed security status of samba please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/samba

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/samba");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-2124");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-10218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14833");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14847");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14902");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-19344");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/samba");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ctdb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14902");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10218");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-samba");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'ctdb', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libnss-winbind', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libpam-winbind', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libsmbclient', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libsmbclient-dev', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libwbclient-dev', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'libwbclient0', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'python-samba', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'registry-tools', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'samba', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'samba-common', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'samba-common-bin', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'samba-dev', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'samba-dsdb-modules', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'samba-libs', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'samba-testsuite', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'samba-vfs-modules', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'smbclient', 'reference': '2:4.9.5+dfsg-5+deb10u4'},
    {'release': '10.0', 'prefix': 'winbind', 'reference': '2:4.9.5+dfsg-5+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / libpam-winbind / libsmbclient / etc');
}
