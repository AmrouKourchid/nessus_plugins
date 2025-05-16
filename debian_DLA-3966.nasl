#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3966. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211850);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id(
    "CVE-2020-10735",
    "CVE-2020-29651",
    "CVE-2021-3737",
    "CVE-2021-28861",
    "CVE-2022-0391",
    "CVE-2022-45061",
    "CVE-2023-27043",
    "CVE-2024-9287"
  );

  script_name(english:"Debian dla-3966 : pypy3 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3966 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3966-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Andrej Shadura
    November 26, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : pypy3
    Version        : 7.3.5+dfsg-2+deb11u4
    CVE ID         : CVE-2020-10735 CVE-2020-29651 CVE-2021-3737 CVE-2021-28861
                     CVE-2022-0391 CVE-2022-45061 CVE-2023-27043 CVE-2024-9287

    Multiple vulnerabilities have been fixed in pypy3, an alternative
    implementation of the Python 3.x language.

    CVE-2020-10735

        A flaw was found in Python. In algorithms with quadratic time
        complexity using non-binary bases, when using int(text), a system
        could take 50ms to parse an int string with 100,000 digits and 5s
        for 1,000,000 digits (float, decimal, int.from_bytes(), and int()
        for binary bases 2, 4, 8, 16, and 32 are not affected). The highest
        threat from this vulnerability is to system availability.

    CVE-2020-29651

        A denial of service via regular expression in the py.path.svnwc
        component of py (aka python-py) through 1.9.0 could be used by
        attackers to cause a compute-time denial of service attack by
        supplying malicious input to the blame functionality.
        python-py is a part of the pypy3 distribution.

    CVE-2021-3737

        A flaw was found in Python. An improperly handled HTTP response in the
        HTTP client code of Python may allow a remote attacker, who controls
        the HTTP server, to make the client script enter an infinite loop,
        consuming CPU time. The highest threat from this vulnerability is
        to system availability.

    CVE-2021-28861

        Python has an open redirection vulnerability in lib/http/server.py
        due to no protection against multiple (/) at the beginning of URI
        path which may leads to information disclosure.
        NOTE: this is disputed by a third party because the http.server.html
        documentation page states Warning: http.server is not recommended
        for production. It only implements basic security checks.

    CVE-2022-0391

        A flaw was found in Python within the urllib.parse module. This
        module helps break Uniform Resource Locator (URL) strings into
        components. The issue involves how the urlparse method does not
        sanitize input and allows characters like '\r' and '\n' in the URL
        path. This flaw allows an attacker to input a crafted URL, leading
        to injection attacks.

    CVE-2022-45061

        An unnecessary quadratic algorithm exists in one path when processing
        some inputs to the IDNA (RFC 3490) decoder, such that a crafted,
        unreasonably long name being presented to the decoder could lead to a
        CPU denial of service. Hostnames are often supplied by remote servers
        that could be controlled by a malicious actor; in such a scenario,
        they could trigger excessive CPU consumption on the client attempting
        to make use of an attacker-supplied supposed hostname. For example,
        the attack payload could be placed in the Location header of an HTTP
        response with status code 302.

    CVE-2023-27043

        The email module of Python incorrectly parses e-mail addresses that
        contain a special character. The wrong portion of an RFC2822 header
        is identified as the value of the addr-spec. In some applications,
        an attacker can bypass a protection mechanism in which application
        access is granted only after verifying receipt of e-mail to a
        specific domain (e.g., only @company.example.com addresses may
        be used for signup). This occurs in email/_parseaddr.py.

    CVE-2024-9287

        A vulnerability has been found in the `venv` module and CLI where
        path names provided when creating a virtual environment were not
        quoted properly, allowing the creator to inject commands into virtual
        environment activation scripts (ie source venv/bin/activate). This
        means that attacker-controlled virtual environments are able to
        run commands when the virtual environment is activated. Virtual
        environments which are not created by an attacker or which aren't
        activated before being used (ie ./venv/bin/python) are not
        affected.v

    For Debian 11 bullseye, these problems have been fixed in version
    7.3.5+dfsg-2+deb11u4.

    We recommend that you upgrade your pypy3 packages.

    For the detailed security status of pypy3 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/pypy3

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/pypy3");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29651");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3737");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0391");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27043");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-9287");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/pypy3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pypy3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0391");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-9287");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-27043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-lib-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy3-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'pypy3', 'reference': '7.3.5+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'pypy3-dev', 'reference': '7.3.5+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'pypy3-doc', 'reference': '7.3.5+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'pypy3-lib', 'reference': '7.3.5+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'pypy3-lib-testsuite', 'reference': '7.3.5+dfsg-2+deb11u4'},
    {'release': '11.0', 'prefix': 'pypy3-tk', 'reference': '7.3.5+dfsg-2+deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pypy3 / pypy3-dev / pypy3-doc / pypy3-lib / pypy3-lib-testsuite / etc');
}
