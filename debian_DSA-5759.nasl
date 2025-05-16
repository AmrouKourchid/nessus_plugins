#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5759. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206226);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2024-0397", "CVE-2024-4032", "CVE-2024-8088");

  script_name(english:"Debian dsa-5759 : idle-python3.11 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5759 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5759-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    August 27, 2024                       https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : python3.11
    CVE ID         : CVE-2024-0397 CVE-2024-4032 CVE-2024-8088

    Multiple security issues were discovered in Python, a high-level,
    interactive, object-oriented language:

    CVE-2024-0397

        A race condition in the ssl module was found when accessing
        CA certificates.

    CVE-2024-4032

        The ipaddress module contained incorrect information whether
        some ipv4 and ipv6 address ranges are designated as globally
        reachable or private.

    CVE-2024-8088

        Incorrect handling of path names in the zipfile module could
        result in an infinite loop when processing a zip archive
        (resulting in denial of service)

    For the stable distribution (bookworm), these problems have been fixed in
    version 3.11.2-6+deb12u3.

    We recommend that you upgrade your python3.11 packages.

    For the detailed security status of python3.11 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python3.11

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/python3.11");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-0397");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-4032");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-8088");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/python3.11");
  script_set_attribute(attribute:"solution", value:
"Upgrade the idle-python3.11 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0397");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-4032");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-8088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.11-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.11-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.11-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.11-venv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'idle-python3.11', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'libpython3.11', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'libpython3.11-dbg', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'libpython3.11-dev', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'libpython3.11-minimal', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'libpython3.11-stdlib', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'libpython3.11-testsuite', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11-dbg', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11-dev', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11-doc', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11-examples', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11-full', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11-minimal', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11-nopie', 'reference': '3.11.2-6+deb12u3'},
    {'release': '12.0', 'prefix': 'python3.11-venv', 'reference': '3.11.2-6+deb12u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python3.11 / libpython3.11 / libpython3.11-dbg / etc');
}
