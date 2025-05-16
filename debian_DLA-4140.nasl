#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4140. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(234885);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/27");

  script_cve_id(
    "CVE-2025-2784",
    "CVE-2025-32049",
    "CVE-2025-32050",
    "CVE-2025-32052",
    "CVE-2025-32053",
    "CVE-2025-32906",
    "CVE-2025-32907",
    "CVE-2025-32909",
    "CVE-2025-32910",
    "CVE-2025-32911",
    "CVE-2025-32912",
    "CVE-2025-32913",
    "CVE-2025-32914"
  );

  script_name(english:"Debian dla-4140 : gir1.2-soup-2.4 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4140 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4140-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Andreas Henriksson
    April 27, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libsoup2.4
    Version        : 2.72.0-2+deb11u2
    CVE ID         : CVE-2025-2784 CVE-2025-32050 CVE-2025-32052 CVE-2025-32053
                     CVE-2025-32906 CVE-2025-32909 CVE-2025-32910 CVE-2025-32911
                     CVE-2025-32912 CVE-2025-32913 CVE-2025-32914
    Debian Bug     : 1091502 1102208 1102212 1102214 1102215 1103521 1103517
                     1103516 1103515 1103267 1103512

    Several security vulnerabilities have been discovered in libsoup2.4, a http
    client/server library popularly used in GNOME, et.al.

    CVE-2025-2784

        The package is vulnerable to a heap buffer over-read when sniffing content
        via the skip_insight_whitespace() function. Libsoup clients may read one
        byte out-of-bounds in response to a crafted HTTP response by an HTTP
        server.

    CVE-2025-32050

        The libsoup append_param_quoted() function may contain an overflow bug
        resulting in a buffer under-read.

    CVE-2025-32052

        A vulnerability in the sniff_unknown() function may lead to heap buffer
        over-read.

    CVE-2025-32053

        A vulnerability in sniff_feed_or_html() and skip_insignificant_space()
        functions may lead to a heap buffer over-read.

    CVE-2025-32906

        The soup_headers_parse_request() function may be vulnerable to an
        out-of-bound read. This flaw allows a malicious user to use a specially
        crafted HTTP request to crash the HTTP server.

    CVE-2025-32909

        SoupContentSniffer may be vulnerable to a NULL pointer dereference in the
        sniff_mp4 function. The HTTP server may cause the libsoup client to crash.

    CVE-2025-32910

        A flaw was found in libsoup, where soup_auth_digest_authenticate() is
        vulnerable to a NULL pointer dereference. This issue may cause the libsoup
        client to crash.

    CVE-2025-32911

        Vulnerable to a use-after-free memory issue not on the heap in the
        soup_message_headers_get_content_disposition() function.
        This flaw allows a malicious HTTP client to cause memory corruption in the
        libsoup server.

    CVE-2025-32912

        SoupAuthDigest is vulnerable to a NULL pointer dereference. The HTTP server
        may cause the libsoup client to crash.

    CVE-2025-32913

        The soup_message_headers_get_content_disposition() function is vulnerable
        to a NULL pointer dereference. This flaw allows a malicious HTTP peer to
        crash a libsoup client or server that uses this function.

    CVE-2025-32914

        The soup_multipart_new_from_message() function is vulnerable to an
        out-of-bounds read. This flaw allows a malicious HTTP client to induce the
        libsoup server to read out of bounds.

    Additionally this update also includes a fix to extend the lifetime
    of a certificate used by the test-suite during build to avoid
    expiring soon.

    Note that this update does *not* yet address CVE-2025-32907 and CVE-2025-32049
    which are still being discussed.

    For Debian 11 bullseye, these problems have been fixed in version
    2.72.0-2+deb11u2.

    We recommend that you upgrade your libsoup2.4 packages.

    For the detailed security status of libsoup2.4 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libsoup2.4

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libsoup2.4");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-2784");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32049");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32050");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32052");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32053");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32906");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32909");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32910");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32911");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32912");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32913");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-32914");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libsoup2.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-soup-2.4 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-soup-2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup-gnome2.4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup-gnome2.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup2.4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup2.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup2.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsoup2.4-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gir1.2-soup-2.4', 'reference': '2.72.0-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libsoup-gnome2.4-1', 'reference': '2.72.0-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libsoup-gnome2.4-dev', 'reference': '2.72.0-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libsoup2.4-1', 'reference': '2.72.0-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libsoup2.4-dev', 'reference': '2.72.0-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libsoup2.4-doc', 'reference': '2.72.0-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libsoup2.4-tests', 'reference': '2.72.0-2+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-soup-2.4 / libsoup-gnome2.4-1 / libsoup-gnome2.4-dev / etc');
}
