#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3638. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(184084);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-44487");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Debian dla-3638 : h2o - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3638
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3638-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Anton Gladky
    October 29, 2023                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : h2o
    Version        : 2.2.5+dfsg2-2+deb10u2
    CVE ID         : CVE-2023-44487
    Debian Bug     : 1054232

    A vulnerability has been identified in h2o, a high-performance web server
    with support for HTTP/2.

    A security vulnerability CVE-2023-44487 was discovered that could potentially
    be exploited to disrupt server operation.

    The vulnerability in the h2o HTTP/2 server was related to the handling of
    certain types of HTTP/2 requests. In certain scenarios, an attacker could
    send a series of malicious requests, causing the server to process them
    rapidly and exhaust system resources.

    The applied upstream patch changes the ABI. Therefore, if your application
    is built against any shared libraries of h2o, you need to rebuild it.
    No Debian package is affected.

    For Debian 10 buster, this problem has been fixed in version
    2.2.5+dfsg2-2+deb10u2.

    We recommend that you upgrade your h2o packages.

    For the detailed security status of h2o please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/h2o

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/h2o");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-44487");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/h2o");
  script_set_attribute(attribute:"solution", value:
"Upgrade the h2o packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:h2o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:h2o-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libh2o-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libh2o-dev-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libh2o-evloop-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libh2o-evloop0.13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libh2o0.13");
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
    {'release': '10.0', 'prefix': 'h2o', 'reference': '2.2.5+dfsg2-2+deb10u2'},
    {'release': '10.0', 'prefix': 'h2o-doc', 'reference': '2.2.5+dfsg2-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libh2o-dev', 'reference': '2.2.5+dfsg2-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libh2o-dev-common', 'reference': '2.2.5+dfsg2-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libh2o-evloop-dev', 'reference': '2.2.5+dfsg2-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libh2o-evloop0.13', 'reference': '2.2.5+dfsg2-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libh2o0.13', 'reference': '2.2.5+dfsg2-2+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'h2o / h2o-doc / libh2o-dev / libh2o-dev-common / libh2o-evloop-dev / etc');
}
