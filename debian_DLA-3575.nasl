#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3575. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181697);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2021-23336",
    "CVE-2022-0391",
    "CVE-2022-48560",
    "CVE-2022-48565",
    "CVE-2022-48566",
    "CVE-2023-24329",
    "CVE-2023-40217"
  );

  script_name(english:"Debian dla-3575 : idle-python2.7 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3575 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3575-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Helmut Grohne
    September 20, 2023                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : python2.7
    Version        : 2.7.16-2+deb10u3
    CVE ID         : CVE-2021-23336 CVE-2022-0391 CVE-2022-48560 CVE-2022-48565
                     CVE-2022-48566 CVE-2023-24329 CVE-2023-40217

    This update fixes multiple vulnerabilities concerning the urlparse module as
    well as vulnerabilities concerning the heapq, hmac, plistlib and ssl modules.

    CVE-2021-23336

        Python was vulnerable to Web Cache Poisoning via urlparse.parse_qsl and
        urlparse.parse_qs by using a vector called parameter cloaking. When the
        attacker can separate query parameters using a semicolon (;), they can
        cause a difference in the interpretation of the request between the proxy
        (running with default configuration) and the server. This can result in
        malicious requests being cached as completely safe ones, as the proxy would
        usually not see the semicolon as a separator, and therefore would not
        include it in a cache key of an unkeyed parameter.

    CVE-2022-0391

        The urlparse module helps break Uniform Resource Locator (URL) strings into
        components. The issue involves how the urlparse method does not sanitize
        input and allows characters like '\r' and '\n' in the URL path.  This flaw
        allows an attacker to input a crafted URL, leading to injection attacks.

    CVE-2022-48560

        A use-after-free exists in Python via heappushpop in heapq.

    CVE-2022-48565

        An XML External Entity (XXE) issue was discovered in Python.  The plistlib
        module no longer accepts entity declarations in XML plist files to avoid
        XML vulnerabilities.

    CVE-2022-48566

        An issue was discovered in compare_digest in Lib/hmac.py in Python.
        Constant-time-defeating optimisations were possible in the accumulator
        variable in hmac.compare_digest.

    CVE-2023-24329

        An issue in the urlparse component of Python allows attackers to bypass
        blocklisting methods by supplying a URL that starts with blank characters.

    CVE-2023-40217

        The issue primarily affects servers written in Python (such as HTTP
        servers) that use TLS client authentication. If a TLS server-side socket is
        created, receives data into the socket buffer, and then is closed quickly,
        there is a brief window where the SSLSocket instance will detect the socket
        as not connected and won't initiate a handshake, but buffered data will
        still be readable from the socket buffer.  This data will not be
        authenticated if the server-side TLS peer is expecting client certificate
        authentication, and is indistinguishable from valid TLS stream data. Data
        is limited in size to the amount that will fit in the buffer. (The TLS
        connection cannot directly be used for data exfiltration because the
        vulnerable code path requires that the connection be closed on
        initialization of the SSLSocket.)


    For Debian 10 buster, these problems have been fixed in version
    2.7.16-2+deb10u3.

    We recommend that you upgrade your python2.7 packages.

    For the detailed security status of python2.7 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python2.7

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/python2.7");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23336");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0391");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48560");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48565");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-48566");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24329");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40217");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/python2.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the idle-python2.7 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0391");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-48565");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-40217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-minimal");
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
    {'release': '10.0', 'prefix': 'idle-python2.7', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libpython2.7', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libpython2.7-dbg', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libpython2.7-dev', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libpython2.7-minimal', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libpython2.7-stdlib', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libpython2.7-testsuite', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'python2.7', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'python2.7-dbg', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'python2.7-dev', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'python2.7-doc', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'python2.7-examples', 'reference': '2.7.16-2+deb10u3'},
    {'release': '10.0', 'prefix': 'python2.7-minimal', 'reference': '2.7.16-2+deb10u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python2.7 / libpython2.7 / libpython2.7-dbg / libpython2.7-dev / etc');
}
