#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3592. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(182409);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2023-26048",
    "CVE-2023-26049",
    "CVE-2023-36479",
    "CVE-2023-40167"
  );
  script_xref(name:"IAVB", value:"2023-B-0082-S");

  script_name(english:"Debian dla-3592 : jetty9 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3592 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3592-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    September 30, 2023                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : jetty9
    Version        : 9.4.16-0+deb10u3
    CVE ID         : CVE-2023-26048 CVE-2023-26049 CVE-2023-36479 CVE-2023-40167

    Multiple security vulnerabilities were found in Jetty, a Java based web server
    and servlet engine.

    The org.eclipse.jetty.servlets.CGI class has been deprecated. It is potentially
    unsafe to use it. The upstream developers of Jetty recommend to use Fast CGI
    instead. See also CVE-2023-36479.

    CVE-2023-26048

        In affected versions servlets with multipart support (e.g. annotated with
        `@MultipartConfig`) that call `HttpServletRequest.getParameter()` or
        `HttpServletRequest.getParts()` may cause `OutOfMemoryError` when the
        client sends a multipart request with a part that has a name but no
        filename and very large content. This happens even with the default
        settings of `fileSizeThreshold=0` which should stream the whole part
        content to disk.

    CVE-2023-26049

        Nonstandard cookie parsing in Jetty may allow an attacker to smuggle
        cookies within other cookies, or otherwise perform unintended behavior by
        tampering with the cookie parsing mechanism.

    CVE-2023-40167

        Prior to this version Jetty accepted the `+` character proceeding the
        content-length value in a HTTP/1 header field. This is more permissive than
        allowed by the RFC and other servers routinely reject such requests with
        400 responses. There is no known exploit scenario, but it is conceivable
        that request smuggling could result if jetty is used in combination with a
        server that does not close the connection after sending such a 400
        response.

    CVE-2023-36479

        Users of the CgiServlet with a very specific command structure may have the
        wrong command executed. If a user sends a request to a
        org.eclipse.jetty.servlets.CGI Servlet for a binary with a space in its
        name, the servlet will escape the command by wrapping it in quotation
        marks. This wrapped command, plus an optional command prefix, will then be
        executed through a call to Runtime.exec. If the original binary name
        provided by the user contains a quotation mark followed by a space, the
        resulting command line will contain multiple tokens instead of one.

    For Debian 10 buster, these problems have been fixed in version
    9.4.16-0+deb10u3.

    We recommend that you upgrade your jetty9 packages.

    For the detailed security status of jetty9 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/jetty9

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/jetty9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-26048");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-26049");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36479");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40167");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/jetty9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the jetty9 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40167");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jetty9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjetty9-extra-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjetty9-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'jetty9', 'reference': '9.4.16-0+deb10u3'},
    {'release': '10.0', 'prefix': 'libjetty9-extra-java', 'reference': '9.4.16-0+deb10u3'},
    {'release': '10.0', 'prefix': 'libjetty9-java', 'reference': '9.4.16-0+deb10u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jetty9 / libjetty9-extra-java / libjetty9-java');
}
