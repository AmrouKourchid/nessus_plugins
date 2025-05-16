#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3336. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171837);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2021-3664",
    "CVE-2021-27515",
    "CVE-2022-0512",
    "CVE-2022-0639",
    "CVE-2022-0686",
    "CVE-2022-0691"
  );

  script_name(english:"Debian dla-3336 : node-url-parse - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3336 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3336-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    February 23, 2023                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : node-url-parse
    Version        : 1.2.0-2+deb10u2
    CVE ID         : CVE-2021-3664 CVE-2021-27515 CVE-2022-0512 CVE-2022-0639
                     CVE-2022-0686 CVE-2022-0691
    Debian Bug     : 985110 991577

    Multiple vulnerabilities were found in node-types-url-parse, a Node.js
    module used to parse URLs, which may result in authorization bypass or
    redirection to untrusted sites.

    CVE-2021-3664

        url-parse mishandles certain uses of a single (back)slash such as
        https:\ & https:/ and interprets the URI as a relative path.
        Browsers accept a single backslash after the protocol, and treat it
        as a normal slash, while url-parse sees it as a relative path.
        Depending on library usage, this may result in allow/block list
        bypasses, SSRF attacks, open redirects, or other undesired behavior.

    CVE-2021-27515

        Using backslash in the protocol is valid in the browser, while
        url-parse thinks it's a relative path.  An application that
        validates a URL using url-parse might pass a malicious link.

    CVE-2022-0512

        Incorrect handling of username and password can lead to failure to
        properly identify the hostname, which in turn could result in
        authorization bypass.

    CVE-2022-0639

        Incorrect conversion of `@` characters in protocol in the `href`
        field can lead to lead to failure to properly identify the hostname,
        which in turn could result in authorization bypass.

    CVE-2022-0686

        Rohan Sharma reported that url-parse is unable to find the correct
        hostname when no port number is provided in the URL, such as in
        `http://example.com:`.  This could in turn result in SSRF attacks,
        open redirects or any other vulnerability which depends on the
        `hostname` field of parsed URL.

    CVE-2022-0691

        url-parse is unable to find the correct hostname when the URL
        contains a backspace `\b` character.  This tricks the parser into
        interpreting the URL as a relative path, bypassing all hostname
        checks.  It can also lead to false positive in `extractProtocol()`.

    For Debian 10 buster, these problems have been fixed in version
    1.2.0-2+deb10u2.

    We recommend that you upgrade your node-url-parse packages.

    For the detailed security status of node-url-parse please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/node-url-parse

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/node-url-parse
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?082d3b19");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-27515");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3664");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0512");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0639");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0686");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0691");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/node-url-parse");
  script_set_attribute(attribute:"solution", value:
"Upgrade the node-url-parse packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0691");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-url-parse");
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
    {'release': '10.0', 'prefix': 'node-url-parse', 'reference': '1.2.0-2+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'node-url-parse');
}
