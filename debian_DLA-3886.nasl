#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3886. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(207274);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/14");

  script_cve_id(
    "CVE-2023-30589",
    "CVE-2023-30590",
    "CVE-2023-32559",
    "CVE-2023-46809",
    "CVE-2024-22019",
    "CVE-2024-22025",
    "CVE-2024-27982",
    "CVE-2024-27983"
  );

  script_name(english:"Debian dla-3886 : libnode-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3886 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3886-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    September 14, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : nodejs
    Version        : 12.22.12~dfsg-1~deb11u5
    CVE ID         : CVE-2023-30589 CVE-2023-30590 CVE-2023-32559 CVE-2023-46809
                     CVE-2024-22019 CVE-2024-22025 CVE-2024-27982 CVE-2024-27983

    Node.js a JavaScript runtime environment that executes JavaScript code
    outside a web browser (server side) was vulnerable.

    CVE-2023-30589

        The llhttp parser in the http module in Node does not strictly
        use the CRLF sequence to delimit HTTP requests. This can lead to
        HTTP Request Smuggling (HRS). The CR character (without LF) is
        sufficient to delimit HTTP header fields in the llhttp parser.
        According to RFC7230 section 3, only the CRLF sequence should
        delimit each header-field.

    CVE-2023-30590

        The generateKeys() API function returned from
        crypto.createDiffieHellman() only generates missing (or outdated)
        keys, that is, it only generates a private key if none has been
        set yet, but the function is also needed to compute the
        corresponding public key after calling setPrivateKey(). However,
        the documentation says this API call: Generates private and
        public Diffie-Hellman key values. The documented behavior is very
        different from the actual behavior, and this difference could
        easily lead to security issues.

    CVE-2023-32559

        A privilege escalation vulnerability exists in the experimental
        policy mechanism.
        The use of the deprecated API `process.binding()` can bypass
        the policy mechanism by requiring internal modules and eventually
        take advantage of `process.binding('spawn_sync')` run arbitrary
        code, outside of the limits defined in a `policy.json` file

    CVE-2023-46809

        Node.js versions are vulnerable to the Marvin Attack,
        if PCKS #1 v1.5 padding is allowed when performing RSA descryption
        using a private key.

    CVE-2024-22019

        A vulnerability in Node.js HTTP servers allows an attacker to send a
        specially crafted HTTP request with chunked encoding, leading
        to resource exhaustion and denial of service (DoS).
        The server reads an unbounded number of bytes from a single connection,
        exploiting the lack of limitations on chunk extension bytes.
        The issue can cause CPU and network bandwidth exhaustion, bypassing
        standard safeguards like timeouts and body size limits.

    CVE-2024-22025

        A vulnerability in Node.js has been identified, allowing for a
        Denial of Service (DoS) attack through resource exhaustion when
        using the fetch() function to retrieve content from an untrusted URL.
        The vulnerability stems from the fact that the fetch() function in Node.js
        always decodes Brotli, making it possible for an attacker to cause
        resource exhaustion when fetching content from an untrusted URL.
        An attacker controlling the URL passed into fetch() can exploit this
        vulnerability to exhaust memory, potentially leading to process
        termination, depending on the system configuration.

    CVE-2024-27982

        Malformed headers can lead to HTTP request smuggling. Specifically,
        if a space is placed before a content-length header, it is not
        interpreted correctly, enabling attackers to smuggle in a
        second request within the body of the first.

    CVE-2024-27983

        An attacker can make the Node.js HTTP/2 server completely
        unavailable by sending a small amount of HTTP/2 frames packets
        with a few HTTP/2 frames inside. It is possible to leave some data
        in nghttp2 memory after reset when headers with HTTP/2
        CONTINUATION frame are sent to the server and then a TCP
        connection is abruptly closed by the client triggering the
        Http2Session destructor while header frames are still being
        processed (and stored in memory) causing a race condition.

    For Debian 11 bullseye, these problems have been fixed in version
    12.22.12~dfsg-1~deb11u5.

    We recommend that you upgrade your nodejs packages.

    For the detailed security status of nodejs please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/nodejs

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nodejs");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30589");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30590");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32559");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-46809");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22025");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27982");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27983");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/nodejs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libnode-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30590");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-32559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnode-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnode72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nodejs-doc");
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
    {'release': '11.0', 'prefix': 'libnode-dev', 'reference': '12.22.12~dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'libnode72', 'reference': '12.22.12~dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'nodejs', 'reference': '12.22.12~dfsg-1~deb11u5'},
    {'release': '11.0', 'prefix': 'nodejs-doc', 'reference': '12.22.12~dfsg-1~deb11u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnode-dev / libnode72 / nodejs / nodejs-doc');
}
