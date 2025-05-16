#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3992. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(212690);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2024-52530", "CVE-2024-52531", "CVE-2024-52532");

  script_name(english:"Debian dla-3992 : gir1.2-soup-2.4 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3992 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3992-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Sean Whitton
    December 12, 2024                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libsoup2.4
    Version        : 2.72.0-2+deb11u1
    CVE ID         : CVE-2024-52530 CVE-2024-52531 CVE-2024-52532
    Debian Bug     : 1088812 1089238 1089240

    Multiple vulnerabilities were discovered in libsoup2.4, an HTTP library
    for Gtk+ programs.

    CVE-2024-52530

        In some configurations, HTTP request smuggling is possible because
        null characters at the end of the names of HTTP headers were
        ignored.

    CVE-2024-52531

        There was a buffer overflow in applications that perform conversion
        to UTF-8 in soup_header_parse_param_list_strict.  This could lead to
        memory corruption, crashes or information disclosure.
        (Contrary to the CVE description, it is now believed that input
        received over the network could trigger this.)

    CVE-2024-52532

        An infinite loop in the processing of WebSocket data from clients
        could lead to a denial-of-service problem through memory exhaustion.

    For Debian 11 bullseye, these problems have been fixed in version
    2.72.0-2+deb11u1.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52530");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52531");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52532");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libsoup2.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-soup-2.4 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52530");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-52531");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

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
    {'release': '11.0', 'prefix': 'gir1.2-soup-2.4', 'reference': '2.72.0-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsoup-gnome2.4-1', 'reference': '2.72.0-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsoup-gnome2.4-dev', 'reference': '2.72.0-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsoup2.4-1', 'reference': '2.72.0-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsoup2.4-dev', 'reference': '2.72.0-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsoup2.4-doc', 'reference': '2.72.0-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libsoup2.4-tests', 'reference': '2.72.0-2+deb11u1'}
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
