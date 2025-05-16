#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3477. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177875);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2015-20107",
    "CVE-2020-10735",
    "CVE-2021-3426",
    "CVE-2021-3733",
    "CVE-2021-3737",
    "CVE-2021-4189",
    "CVE-2022-45061"
  );

  script_name(english:"Debian dla-3477 : idle-python3.7 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3477 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3477-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    June 30, 2023                                 https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : python3.7
    Version        : 3.7.3-2+deb10u5
    CVE ID         : CVE-2015-20107 CVE-2020-10735 CVE-2021-3426 CVE-2021-3733
                     CVE-2021-3737 CVE-2021-4189 CVE-2022-45061

    Several vulnerabilities were fixed in the Python3 interpreter.

    CVE-2015-20107

        The mailcap module did not add escape characters into commands
        discovered in the system mailcap file.

    CVE-2020-10735

        Prevent DoS with very large int.

    CVE-2021-3426

        Remove the pydoc getfile feature which could be abused to read
        arbitrary files on the disk.

    CVE-2021-3733

        Regular Expression Denial of Service in urllib's AbstractBasicAuthHandler class.

    CVE-2021-3737

        Infinite loop in the HTTP client code.

    CVE-2021-4189

        Make ftplib not trust the PASV response.

    CVE-2022-45061

        Quadratic time in the IDNA decoder.

    For Debian 10 buster, these problems have been fixed in version
    3.7.3-2+deb10u5.

    We recommend that you upgrade your python3.7 packages.

    For the detailed security status of python3.7 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python3.7

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/python3.7");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2015-20107");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3426");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3737");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4189");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45061");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/python3.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the idle-python3.7 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-venv");
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
    {'release': '10.0', 'prefix': 'idle-python3.7', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-dbg', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-dev', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-minimal', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-stdlib', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-testsuite', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-dbg', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-dev', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-doc', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-examples', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-minimal', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-venv', 'reference': '3.7.3-2+deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python3.7 / libpython3.7 / libpython3.7-dbg / libpython3.7-dev / etc');
}
