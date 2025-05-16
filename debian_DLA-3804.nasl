#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3804. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(194852);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2024-28182");

  script_name(english:"Debian dla-3804 : libnghttp2-14 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3804
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3804-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    April 30, 2024                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : nghttp2
    Version        : 1.36.0-2+deb10u3
    CVE ID         : CVE-2024-28182
    Debian Bug     : 1068415

    Bartek Nowotarskis discovered that nghttp2, a set of programs
    implementing the HTTP/2, keeps reading CONTINUATION frames even after a
    stream is reset to keep HPACK context in sync.  This causes excessive
    CPU usage to decode HPACK stream, which could lead to Denial of Service.

    The issue is mitigated by limiting the number of CONTINUATION frames it
    can accept after a HEADERS frame.  The limit is configurable and
    defaults to 8.

    For Debian 10 buster, this problem has been fixed in version
    1.36.0-2+deb10u3.

    We recommend that you upgrade your nghttp2 packages.

    For the detailed security status of nghttp2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/nghttp2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nghttp2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-28182");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/nghttp2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libnghttp2-14 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28182");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnghttp2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnghttp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnghttp2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nghttp2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nghttp2-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nghttp2-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'libnghttp2-14', 'reference': '1.36.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libnghttp2-dev', 'reference': '1.36.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libnghttp2-doc', 'reference': '1.36.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'nghttp2', 'reference': '1.36.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'nghttp2-client', 'reference': '1.36.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'nghttp2-proxy', 'reference': '1.36.0-2+deb10u3'},
    {'release': '10.0', 'prefix': 'nghttp2-server', 'reference': '1.36.0-2+deb10u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnghttp2-14 / libnghttp2-dev / libnghttp2-doc / nghttp2 / etc');
}
