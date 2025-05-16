#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3998. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(213316);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/21");

  script_cve_id("CVE-2023-43804", "CVE-2023-45803", "CVE-2024-37891");

  script_name(english:"Debian dla-3998 : python3-urllib3 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3998 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3998-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    December 21, 2024                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : python-urllib3
    Version        : 1.26.5-1~exp1+deb11u1
    CVE ID         : CVE-2023-43804 CVE-2023-45803 CVE-2024-37891
    Debian Bug     : 1053626 1054226 1074149 1089507

    Multiple vulnerabilities were found in python-urllib3, an HTTP library
    with thread-safe connection pooling for Python, which could lead to
    information disclosure or authorization bypass.

    CVE-2023-43804

        It was discovered that the cookie request header wasn't stripped
        during cross-origin redirects.  It is therefore possible for a user
        to specify a Cookie header and unknowingly leak information via HTTP
        redirects to a different origin if redirection isn't explicitly
        disabled.

    CVE-2023-45803

        It was discovered that the request body wasn't stripped when an HTTP
        redirect response using status 303 See Other, after the request
        had its method changed from one that could accept a request body
        (like POST) to GET as is required by HTTP RFCs.

    CVE-2024-37891

        It was discovered that the Proxy-Authorization request header isn't
        stripped during cross-origin redirects, when urllib3 is used without
        proxy support.

    For Debian 11 bullseye, these problems have been fixed in version
    1.26.5-1~exp1+deb11u1.

    We recommend that you upgrade your python-urllib3 packages.

    For the detailed security status of python-urllib3 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python-urllib3

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/python-urllib3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb907009");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-43804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45803");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-37891");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/python-urllib3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python3-urllib3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43804");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-urllib3");
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
    {'release': '11.0', 'prefix': 'python3-urllib3', 'reference': '1.26.5-1~exp1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-urllib3');
}
