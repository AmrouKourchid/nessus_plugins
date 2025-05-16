#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4041. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(214900);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id(
    "CVE-2023-47627",
    "CVE-2023-47641",
    "CVE-2023-49081",
    "CVE-2023-49082",
    "CVE-2024-23334",
    "CVE-2024-23829",
    "CVE-2024-27306",
    "CVE-2024-30251",
    "CVE-2024-52304"
  );

  script_name(english:"Debian dla-4041 : python-aiohttp-doc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4041 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4041-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Jochen Sprickerhof
    February 03, 2025                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : python-aiohttp
    Version        : 3.7.4-1+deb11u1
    CVE ID         : CVE-2023-47627 CVE-2023-47641 CVE-2023-49081 CVE-2023-49082
                     CVE-2024-23334 CVE-2024-23829 CVE-2024-27306 CVE-2024-30251
                     CVE-2024-52304
    Debian Bug     :

    Several issues have been found in aiohttp, an asynchronous HTTP
    client/server framework for asyncio and Python. Those issues are related
    to the HTTP parser, link traversal and XSS on the index pages.

    CVE-2023-47627

         The HTTP parser in AIOHTTP has numerous problems with header
         parsing, which could lead to request smuggling. This parser is only
         used when AIOHTTP_NO_EXTENSIONS is enabled (or not using a prebuilt
         wheel).

    CVE-2023-47641

        Affected versions of aiohttp have a security vulnerability regarding
        the inconsistent interpretation of the http protocol. HTTP/1.1 is a
        persistent protocol, if both Content-Length(CL) and
        Transfer-Encoding(TE) header values are present it can lead to
        incorrect interpretation of two entities that parse the HTTP and we
        can poison other sockets with this incorrect interpretation. A
        possible Proof-of-Concept (POC) would be a configuration with a
        reverse proxy(frontend) that accepts both CL and TE headers and
        aiohttp as backend. As aiohttp parses anything with chunked, we can
        pass a chunked123 as TE, the frontend entity will ignore this header
        and will parse Content-Length. The impact of this vulnerability is
        that it is possible to bypass any proxy rule, poisoning sockets to
        other users like passing Authentication Headers, also if it is
        present an Open Redirect an attacker could combine it to redirect
        random users to another website and log the request.

    CVE-2023-49081

        Improper validation made it possible for an attacker to modify the
        HTTP request (e.g. to insert a new header) or create a new HTTP
        request if the attacker controls the HTTP version. The vulnerability
        only occurs if the attacker can control the HTTP version of the
        request.

    CVE-2023-49082

        Improper validation makes it possible for an attacker to modify the
        HTTP request (e.g. insert a new header) or even create a new HTTP
        request if the attacker controls the HTTP method. The vulnerability
        occurs only if the attacker can control the HTTP method (GET, POST
        etc.) of the request. If the attacker can control the HTTP version
        of the request it will be able to modify the request (request
        smuggling).

    CVE-2024-23334

        When using aiohttp as a web server and configuring static routes, it
        is necessary to specify the root path for static files.
        Additionally, the option 'follow_symlinks' can be used to determine
        whether to follow symbolic links outside the static root directory.
        When 'follow_symlinks' is set to True, there is no validation to
        check if reading a file is within the root directory. This can lead
        to directory traversal vulnerabilities, resulting in unauthorized
        access to arbitrary files on the system, even when symlinks are not
        present. Disabling follow_symlinks and using a reverse proxy are
        encouraged mitigations.

    CVE-2024-23829

        Security-sensitive parts of the Python HTTP parser retained minor
        differences in allowable character sets, that must trigger error
        handling to robustly match frame boundaries of proxies in order to
        protect against injection of additional requests. Additionally,
        validation could trigger exceptions that were not handled
        consistently with processing of other malformed input. Being more
        lenient than internet standards require could, depending on
        deployment environment, assist in request smuggling. The unhandled
        exception could cause excessive resource consumption on the
        application server and/or its logging facilities.

    CVE-2024-27306

        A XSS vulnerability exists on index pages for static file handling.

    CVE-2024-30251

         In affected versions an attacker can send a specially crafted POST
         (multipart/form-data) request. When the aiohttp server processes
         it, the server will enter an infinite loop and be unable to process
         any further requests. An attacker can stop the application from
         serving requests after sending a single request.

    CVE-2024-52304

        The Python parser parses newlines in chunk extensions incorrectly
        which can lead to request smuggling vulnerabilities under certain
        conditions. If a pure Python version of aiohttp is installed (i.e.
        without the usual C extensions) or `AIOHTTP_NO_EXTENSIONS` is
        enabled, then an attacker may be able to execute a request smuggling
        attack to bypass certain firewalls or proxy protections.

    For Debian 11 bullseye, these problems have been fixed in version
    3.7.4-1+deb11u1.

    We recommend that you upgrade your python-aiohttp packages.

    For the detailed security status of python-aiohttp please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python-aiohttp

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/python-aiohttp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b73efdc");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-47627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-47641");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49081");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49082");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23334");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27306");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-30251");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52304");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/python-aiohttp");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python-aiohttp-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23334");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-52304");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-aiohttp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-aiohttp-dbg");
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
    {'release': '11.0', 'prefix': 'python-aiohttp-doc', 'reference': '3.7.4-1+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-aiohttp', 'reference': '3.7.4-1+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-aiohttp-dbg', 'reference': '3.7.4-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-aiohttp-doc / python3-aiohttp / python3-aiohttp-dbg');
}
