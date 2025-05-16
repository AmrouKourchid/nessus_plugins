#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3856. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206214);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/26");

  script_cve_id("CVE-2024-34078");

  script_name(english:"Debian dla-3856 : python3-html-sanitizer - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by a vulnerability as referenced in the dla-3856
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3856-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                           Chris Lamb
    August 26, 2024                               https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : python-html-sanitizer
    Version        : 1.9.1-2+deb11u1
    CVE ID         : CVE-2024-34078
    Debian Bug     : 1070710

    It was discovered that there was a sanitisation bypass issue in
    python-html-sanitizer, a library used ensure that user-specified
    content cannot inject HTML or JavaScript into a webpage.

    If the default keep_typographic_whitespace=False value was set,
    malicous users could have exploited the fact that some Unicode
    characters normalise to chevrons, which allowed specially-crafted
    HTML to escape sanitization.

    For Debian 11 bullseye, this problem has been fixed in version
    1.9.1-2+deb11u1.

    We recommend that you upgrade your python-html-sanitizer packages.

    For the detailed security status of python-html-sanitizer please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python-html-sanitizer

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/python-html-sanitizer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bff5c7d4");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-34078");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/python-html-sanitizer");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python3-html-sanitizer packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-html-sanitizer");
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
    {'release': '11.0', 'prefix': 'python3-html-sanitizer', 'reference': '1.9.1-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-html-sanitizer');
}
