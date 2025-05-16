#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3970. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211959);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2022-39348",
    "CVE-2023-46137",
    "CVE-2024-41671",
    "CVE-2024-41810"
  );

  script_name(english:"Debian dla-3970 : python3-twisted - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3970 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3970-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Sylvain Beucler
    November 28, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : twisted
    Version        : 20.3.0-7+deb11u2
    CVE ID         : CVE-2022-39348 CVE-2023-46137 CVE-2024-41671 CVE-2024-41810
    Debian Bug     : 1023359 1054913 1077679 1077680

    Multiple security issues were found in Twisted, an event-based framework
    for internet applications, which could result in incorrect ordering of
    HTTP requests or cross-site scripting.

    CVE-2022-39348

        When the host header does not match a configured host
        `twisted.web.vhost.NameVirtualHost` will return a `NoResource`
        resource which renders the Host header unescaped into the 404
        response allowing HTML and script injection. In practice this
        should be very difficult to exploit as being able to modify the
        Host header of a normal HTTP request implies that one is already
        in a privileged position.

    CVE-2023-46137

        When sending multiple HTTP requests in one TCP packet, twisted.web
        will process the requests asynchronously without guaranteeing the
        response order. If one of the endpoints is controlled by an
        attacker, the attacker can delay the response on purpose to
        manipulate the response of the second request when a victim
        launched two requests using HTTP pipeline.

    CVE-2024-41671

        The HTTP 1.0 and 1.1 server provided by twisted.web could process
        pipelined HTTP requests out-of-order, possibly resulting in
        information disclosure.

    CVE-2024-41810

        The `twisted.web.util.redirectTo` function contains an HTML
        injection vulnerability. If application code allows an attacker to
        control the redirect URL this vulnerability may result in
        Reflected Cross-Site Scripting (XSS) in the redirect response HTML
        body.

    For Debian 11 bullseye, these problems have been fixed in version
    20.3.0-7+deb11u2.

    We recommend that you upgrade your twisted packages.

    For the detailed security status of twisted please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/twisted

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/twisted");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39348");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46137");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41671");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41810");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/twisted");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python3-twisted packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41810");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:twisted-doc");
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
    {'release': '11.0', 'prefix': 'python3-twisted', 'reference': '20.3.0-7+deb11u2'},
    {'release': '11.0', 'prefix': 'python3-twisted-bin', 'reference': '20.3.0-7+deb11u2'},
    {'release': '11.0', 'prefix': 'python3-twisted-bin-dbg', 'reference': '20.3.0-7+deb11u2'},
    {'release': '11.0', 'prefix': 'twisted-doc', 'reference': '20.3.0-7+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-twisted / python3-twisted-bin / python3-twisted-bin-dbg / etc');
}
