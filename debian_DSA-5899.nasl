#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5899. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(234140);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2024-54551",
    "CVE-2025-24208",
    "CVE-2025-24209",
    "CVE-2025-24213",
    "CVE-2025-24216",
    "CVE-2025-24264",
    "CVE-2025-30427"
  );

  script_name(english:"Debian dsa-5899 : gir1.2-javascriptcoregtk-4.0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5899 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5899-1                   security@debian.org
    https://www.debian.org/security/                           Alberto Garcia
    April 10, 2025                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : webkit2gtk
    CVE ID         : CVE-2024-54551 CVE-2025-24208 CVE-2025-24209 CVE-2025-24213
                     CVE-2025-24216 CVE-2025-24264 CVE-2025-30427

    The following vulnerabilities have been discovered in the WebKitGTK
    web engine:

    CVE-2024-54551

        ajajfxhj discovered that processing web content may lead to a
        denial-of-service.

    CVE-2025-24208

        Muhammad Zaid Ghifari and Kalimantan Utara discovered that loading
        a malicious iframe may lead to a cross-site scripting attack.

    CVE-2025-24209

        Francisco Alonso and an anonymous researcher discovered that
        processing maliciously crafted web content may lead to an
        unexpected process crash.

    CVE-2025-24213

        The Google V8 Security Team discovered that a type confusion issue
        could lead to memory corruption. Note that this CVE is fixed only
        on ARM architectures.  x86_64 is not vulnerable, x86 is not
        vulnerable when the SSE2 instruction set is enabled; but other
        architectures remain vulnerable.

    CVE-2025-24216

        Paul Bakker discovered that processing maliciously crafted web
        content may lead to an unexpected Safari crash.

    CVE-2025-24264

        Gary Kwong and an anonymous researcher discovered that processing
        maliciously crafted web content may lead to an unexpected crash.

    CVE-2025-30427

        rheza discovered that processing maliciously crafted web content
        may lead to an unexpected crash.

    For the stable distribution (bookworm), these problems have been fixed in
    version 2.48.1-2~deb12u1.

    We recommend that you upgrade your webkit2gtk packages.

    For the detailed security status of webkit2gtk please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/webkit2gtk

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/webkit2gtk");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-54551");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-24208");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-24209");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-24213");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-24216");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-24264");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-30427");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/webkit2gtk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-javascriptcoregtk-4.0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30427");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-24264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-javascriptcoregtk-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-javascriptcoregtk-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-javascriptcoregtk-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-webkit-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-webkit2-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-webkit2-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-4.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-6.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjavascriptcoregtk-6.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.0-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkit2gtk-4.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkitgtk-6.0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwebkitgtk-6.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit2gtk-driver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '12.0', 'prefix': 'gir1.2-javascriptcoregtk-4.0', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-javascriptcoregtk-4.1', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-javascriptcoregtk-6.0', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-webkit-6.0', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-webkit2-4.0', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'gir1.2-webkit2-4.1', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.0-18', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.0-bin', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.0-dev', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.1-0', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-4.1-dev', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-6.0-1', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libjavascriptcoregtk-6.0-dev', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.0-37', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.0-dev', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.0-doc', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.1-0', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkit2gtk-4.1-dev', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkitgtk-6.0-4', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'libwebkitgtk-6.0-dev', 'reference': '2.48.1-2~deb12u1'},
    {'release': '12.0', 'prefix': 'webkit2gtk-driver', 'reference': '2.48.1-2~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-javascriptcoregtk-4.0 / gir1.2-javascriptcoregtk-4.1 / etc');
}
