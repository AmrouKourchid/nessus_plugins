#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5484. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(180206);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-38633");

  script_name(english:"Debian DSA-5484-1 : librsvg - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5484
advisory.

    Zac Sims discovered a directory traversal in the URL decoder of librsvg, a SAX-based renderer library for
    SVG files, which could result in read of arbitrary files when processing a specially crafted SVG file with
    an XInclude element. For the oldstable distribution (bullseye), this problem has been fixed in version
    2.50.3+dfsg-1+deb11u1. For the stable distribution (bookworm), this problem has been fixed in version
    2.54.7+dfsg-1~deb12u1. We recommend that you upgrade your librsvg packages. For the detailed security
    status of librsvg please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/librsvg

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1041810");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/librsvg");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5484");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38633");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/librsvg");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/librsvg");
  script_set_attribute(attribute:"solution", value:
"Upgrade the librsvg packages.

For the stable distribution (bookworm), this problem has been fixed in version 2.54.7+dfsg-1~deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38633");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-rsvg-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gir1.2-rsvg-2.0', 'reference': '2.50.3+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'librsvg2-2', 'reference': '2.50.3+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'librsvg2-bin', 'reference': '2.50.3+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'librsvg2-common', 'reference': '2.50.3+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'librsvg2-dev', 'reference': '2.50.3+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'librsvg2-doc', 'reference': '2.50.3+dfsg-1+deb11u1'},
    {'release': '12.0', 'prefix': 'gir1.2-rsvg-2.0', 'reference': '2.54.7+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librsvg2-2', 'reference': '2.54.7+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librsvg2-bin', 'reference': '2.54.7+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librsvg2-common', 'reference': '2.54.7+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librsvg2-dev', 'reference': '2.54.7+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librsvg2-doc', 'reference': '2.54.7+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'librsvg2-tests', 'reference': '2.54.7+dfsg-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-rsvg-2.0 / librsvg2-2 / librsvg2-bin / librsvg2-common / etc');
}
