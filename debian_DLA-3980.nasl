#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3980. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211991);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/02");

  script_cve_id(
    "CVE-2015-20107",
    "CVE-2020-10735",
    "CVE-2021-3426",
    "CVE-2021-3733",
    "CVE-2021-3737",
    "CVE-2021-4189",
    "CVE-2021-28861",
    "CVE-2021-29921",
    "CVE-2022-42919",
    "CVE-2022-45061",
    "CVE-2023-6597",
    "CVE-2023-24329",
    "CVE-2023-27043",
    "CVE-2023-40217",
    "CVE-2024-0397",
    "CVE-2024-0450",
    "CVE-2024-4032",
    "CVE-2024-6232",
    "CVE-2024-6923",
    "CVE-2024-7592",
    "CVE-2024-8088",
    "CVE-2024-9287",
    "CVE-2024-11168"
  );

  script_name(english:"Debian dla-3980 : idle-python3.9 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3980 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3980-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    December 02, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : python3.9
    Version        : 3.9.2-1+deb11u2
    CVE ID         : CVE-2015-20107 CVE-2020-10735 CVE-2021-3426 CVE-2021-3733
                     CVE-2021-3737 CVE-2021-4189 CVE-2021-28861 CVE-2021-29921
                     CVE-2022-42919 CVE-2022-45061 CVE-2023-6597 CVE-2023-24329
                     CVE-2023-27043 CVE-2023-40217 CVE-2024-0397 CVE-2024-0450
                     CVE-2024-4032 CVE-2024-6232 CVE-2024-6923 CVE-2024-7592
                     CVE-2024-8088 CVE-2024-9287 CVE-2024-11168
    Debian Bug     : 989195 1070135 1059298 1070133

    Multiple vulnerabilities have been fixed in the Python3 interpreter.

    CVE-2015-20107

        The mailcap module did not add escape characters into commands
        discovered in the system mailcap file

    CVE-2020-10735

        Prevent DoS with very large int

    CVE-2021-3426

        Remove the pydoc getfile feature which could be abused to read
        arbitrary files on the disk

    CVE-2021-3733

        Regular Expression Denial of Service in urllib's
        AbstractBasicAuthHandler class

    CVE-2021-3737

        Infinite loop in the HTTP client code

    CVE-2021-4189

        Make ftplib not trust the PASV response

    CVE-2021-28861

        Open redirection vulnerability in http.server

    CVE-2021-29921

        Leading zeros in IPv4 addresses are no longer tolerated

    CVE-2022-42919

        Don't use Linux abstract sockets for multiprocessing

    CVE-2022-45061

        Quadratic time in the IDNA decoder

    CVE-2023-6597

        tempfile.TemporaryDirectory failure to remove dir

    CVE-2023-24329

        Strip C0 control and space chars in urlsplit

    CVE-2023-27043

        Reject malformed addresses in email.parseaddr()

    CVE-2023-40217

        ssl.SSLSocket bypass of the TLS handshake

    CVE-2024-0397

        Race condition in ssl.SSLContext

    CVE-2024-0450

        Quoted-overlap zipbomb DoS

    CVE-2024-4032

        Incorrect information about private addresses in the ipaddress
        module

    CVE-2024-6232

        ReDoS when parsing tarfile headers

    CVE-2024-6923

        Encode newlines in headers in the email module

    CVE-2024-7592

        Quadratic complexity parsing cookies with backslashes

    CVE-2024-8088

        Infinite loop when iterating over zip archive entry names

    CVE-2024-9287

        venv activation scripts did't quote paths

    CVE-2024-11168

        urllib functions improperly validated bracketed hosts

    For Debian 11 bullseye, these problems have been fixed in version
    3.9.2-1+deb11u2.

    We recommend that you upgrade your python3.9 packages.

    For the detailed security status of python3.9 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python3.9

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/python3.9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2015-20107");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3426");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3737");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4189");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42919");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24329");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27043");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40217");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-6597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0397");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0450");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-11168");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-4032");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-6232");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-6923");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-7592");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-8088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-9287");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/python3.9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the idle-python3.9 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-29921");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-40217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.9-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.9-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.9-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.9-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.9-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.9-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.9-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.9-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.9-venv");
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
    {'release': '11.0', 'prefix': 'idle-python3.9', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libpython3.9', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libpython3.9-dbg', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libpython3.9-dev', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libpython3.9-minimal', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libpython3.9-stdlib', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libpython3.9-testsuite', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3.9', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3.9-dbg', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3.9-dev', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3.9-doc', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3.9-examples', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3.9-full', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3.9-minimal', 'reference': '3.9.2-1+deb11u2'},
    {'release': '11.0', 'prefix': 'python3.9-venv', 'reference': '3.9.2-1+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python3.9 / libpython3.9 / libpython3.9-dbg / libpython3.9-dev / etc');
}
