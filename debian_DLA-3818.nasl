#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3818. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(197924);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id(
    "CVE-2019-17567",
    "CVE-2023-31122",
    "CVE-2023-38709",
    "CVE-2023-45802",
    "CVE-2024-24795",
    "CVE-2024-27316"
  );
  script_xref(name:"IAVA", value:"2021-A-0259-S");
  script_xref(name:"IAVA", value:"2023-A-0572-S");
  script_xref(name:"IAVA", value:"2024-A-0202-S");

  script_name(english:"Debian dla-3818 : apache2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3818 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3818-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    May 24, 2024                                  https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : apache2
    Version        : 2.4.59-1~deb10u1
    CVE ID         : CVE-2019-17567 CVE-2023-31122 CVE-2023-38709 CVE-2023-45802
                     CVE-2024-24795 CVE-2024-27316
    Debian Bug     : 1068412

    Multiple vulnerabilities have been discovered in the Apache HTTP server,
    which may result in HTTP response splitting, denial of service, or
    authorization bypass.

    CVE-2019-17567

         mod_proxy_wstunnel configured on an URL that is not
         necessarily Upgraded by the origin server was tunneling
         the whole connection regardless, thus allowing for subsequent requests
         on the same connection to pass through with no HTTP validation,
         authentication or authorization possibly configured.

    CVE-2023-31122

        An Out-of-bounds Read vulnerability was found in mod_macro.

    CVE-2023-38709

        A faulty input validation was found in the core of Apache
        that allows malicious or exploitable backend/content generators
        to split HTTP responses.

    CVE-2023-45802

        When an HTTP/2 stream was reset (RST frame) by a client, there was a
        time window were the request's memory resources were not reclaimed
        immediately. Instead, de-allocation was deferred to connection close.
        A client could send new requests and resets, keeping the connection
        busy and open and causing the memory footprint to keep on growing.
        On connection close, all resources were reclaimed, but the process
        might run out of memory before that.

    CVE-2024-24795

        HTTP Response splitting in multiple modules in Apache HTTP Server
        allows an attacker that can inject malicious response headers into
        backend applications to cause an HTTP desynchronization attack.

    CVE-2024-27316

        HTTP/2 incoming headers exceeding the limit are temporarily
        buffered in nghttp2 in order to generate an informative HTTP
        413 response. If a client does not stop sending headers, this
        leads to memory exhaustion.

    For Debian 10 buster, these problems have been fixed in version
    2.4.59-1~deb10u1.

    Please note that the fix of CVE-2024-24795, may break unrelated
    CGI-BIN scripts. As part of the security fix, the Apache webserver
    mod_cgi module has stopped relaying the Content-Length field
    of the HTTP reply header from the CGI programs back to the client
    in cases where the connection is to be closed and the client
    is able to read until end-of-file. You may restore legacy
    behavior for trusted scripts by adding the following configuration
    environment variable to the
    Apache configuration, scoped to the <Directory> entry or
    entries in which scripts are being served via CGI,
    SetEnv ap_trust_cgilike_cl yes.
    The definitive fix is to read the whole input,
    re-allocating the input buffer to fit as more input is received
    in CGI-BIN scripts, and and to not trust that
    CONTENT_LENGTH variable is always present.

    We recommend that you upgrade your apache2 packages.

    For the detailed security status of apache2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/apache2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/apache2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-17567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31122");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38709");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27316");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/apache2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the apache2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17567");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-proxy-uwsgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'apache2', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'apache2-bin', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'apache2-data', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'apache2-dev', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'apache2-doc', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'apache2-utils', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libapache2-mod-md', 'reference': '2.4.59-1~deb10u1'},
    {'release': '10.0', 'prefix': 'libapache2-mod-proxy-uwsgi', 'reference': '2.4.59-1~deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / apache2-doc / etc');
}
