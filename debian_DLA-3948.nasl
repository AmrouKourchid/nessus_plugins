#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3948. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(210518);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-6597",
    "CVE-2023-24329",
    "CVE-2023-40217",
    "CVE-2024-0450"
  );

  script_name(english:"Debian dla-3948 : pypy3 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3948 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3948-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Andrej Shadura
    November 07, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : pypy3
    Version        : 7.3.5+dfsg-2+deb11u3
    CVE ID         : CVE-2023-6597 CVE-2023-24329 CVE-2023-40217 CVE-2024-0450
    Debian Bug     :

    Brief introduction

    CVE-2023-6597

        An issue was found in the CPython `tempfile.TemporaryDirectory` class
        affecting versions 3.12.1, 3.11.7, 3.10.13, 3.9.18, and 3.8.18 and
        prior. The tempfile.TemporaryDirectory class would dereference
        symlinks during cleanup of permissions-related errors. This means
        users which can run privileged programs are potentially able to modify
        permissions of files referenced by symlinks in some circumstances.

    CVE-2023-24329

        An issue in the urllib.parse component of Python before 3.11.4 allows
        attackers to bypass blocklisting methods by supplying a URL that starts
        with blank characters.

    CVE-2023-40217

        An issue was discovered in Python before 3.8.18, 3.9.x before 3.9.18,
        3.10.x before 3.10.13, and 3.11.x before 3.11.5. It primarily affects
        servers (such as HTTP servers) that use TLS client authentication. If
        a TLS server-side socket is created, receives data into the socket
        buffer, and then is closed quickly, there is a brief window where
        the SSLSocket instance will detect the socket as not connected and
        won't initiate a handshake, but buffered data will still be readable
        from the socket buffer. This data will not be authenticated if the
        server-side TLS peer is expecting client certificate authentication,
        and is indistinguishable from valid TLS stream data. Data is limited
        in size to the amount that will fit in the buffer. (The TLS connection
        cannot directly be used for data exfiltration because the vulnerable
        code path requires that the connection be closed on initialization
        of the SSLSocket.)

    CVE-2024-0450

        An issue was found in the CPython `zipfile` module affecting versions
        3.12.1, 3.11.7, 3.10.13, 3.9.18, and 3.8.18 and prior. The zipfile
        module is vulnerable to quoted-overlap zip-bombs which exploit
        the zip format to create a zip-bomb with a high compression ratio. The
        fixed versions of CPython makes the zipfile module reject zip archives
        which overlap entries in the archive.

    For Debian 11 bullseye, these problems have been fixed in version
    7.3.5+dfsg-2+deb11u3.

    We recommend that you upgrade your pypy3 packages.

    For the detailed security status of pypy3 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/pypy3

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/pypy3");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24329");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40217");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0450");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/pypy3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pypy3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24329");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-40217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-lib-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-tk");
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
    {'release': '11.0', 'prefix': 'pypy3', 'reference': '7.3.5+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'pypy3-dev', 'reference': '7.3.5+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'pypy3-doc', 'reference': '7.3.5+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'pypy3-lib', 'reference': '7.3.5+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'pypy3-lib-testsuite', 'reference': '7.3.5+dfsg-2+deb11u3'},
    {'release': '11.0', 'prefix': 'pypy3-tk', 'reference': '7.3.5+dfsg-2+deb11u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pypy3 / pypy3-dev / pypy3-doc / pypy3-lib / pypy3-lib-testsuite / etc');
}
