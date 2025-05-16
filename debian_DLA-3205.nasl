#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3205. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168204);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2019-0053",
    "CVE-2020-8284",
    "CVE-2021-40491",
    "CVE-2022-39028"
  );

  script_name(english:"Debian dla-3205 : inetutils-ftp - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3205 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3205-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    November 25, 2022                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : inetutils
    Version        : 2:1.9.4-7+deb10u2
    CVE ID         : CVE-2019-0053 CVE-2021-40491 CVE-2022-39028
    Debian Bug     : 945861 956084 993476

    Several security vulnerabilities were discovered in inetutils, a
    collection of common network programs.

    CVE-2019-0053

        inetutils' telnet client doesn't sufficiently validate environment
        variables, which can lead to stack-based buffer overflows.  This
        issue is limited to local exploitation from restricted shells.

    CVE-2021-40491

        inetutils' ftp client before 2.2 does not validate addresses
        returned by PSV/LSPV responses to make sure they match the server
        address.  A malicious server can exploit this flaw to reach services
        in the client's private network.  (This is similar to curl's
        CVE-2020-8284.)

    CVE-2022-39028

        inetutils's telnet server through 2.3 has a NULL pointer dereference
        which a client can trigger by sending 0xff 0xf7 or 0xff 0xf8.  In a
        typical installation, the telnetd application would crash but the
        telnet service would remain available through inetd.  However, if the
        telnetd application has many crashes within a short time interval,
        the telnet service would become unavailable after inetd logs a
        telnet/tcp server failing (looping), service terminated error.

    For Debian 10 buster, these problems have been fixed in version
    2:1.9.4-7+deb10u2.

    We recommend that you upgrade your inetutils packages.

    For the detailed security status of inetutils please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/inetutils

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/inetutils");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-0053");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-8284");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40491");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39028");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/inetutils");
  script_set_attribute(attribute:"solution", value:
"Upgrade the inetutils-ftp packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0053");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-inetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-syslogd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-talk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-talkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils-traceroute");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'release': '10.0', 'prefix': 'inetutils-ftp', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-ftpd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-inetd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-ping', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-syslogd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-talk', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-talkd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-telnet', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-telnetd', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-tools', 'reference': '2:1.9.4-7+deb10u2'},
    {'release': '10.0', 'prefix': 'inetutils-traceroute', 'reference': '2:1.9.4-7+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'inetutils-ftp / inetutils-ftpd / inetutils-inetd / inetutils-ping / etc');
}
