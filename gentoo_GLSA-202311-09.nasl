#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202311-09.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(186294);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/09");

  script_cve_id(
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-41715",
    "CVE-2022-41717",
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24534",
    "CVE-2023-24536",
    "CVE-2023-24537",
    "CVE-2023-24538",
    "CVE-2023-29402",
    "CVE-2023-29403",
    "CVE-2023-29404",
    "CVE-2023-29405",
    "CVE-2023-29406",
    "CVE-2023-29409",
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39320",
    "CVE-2023-39321",
    "CVE-2023-39322",
    "CVE-2023-39323",
    "CVE-2023-39325",
    "CVE-2023-44487"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"GLSA-202311-09 : Go: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202311-09 (Go: Multiple Vulnerabilities)

  - Reader.Read does not set a limit on the maximum size of file headers. A maliciously crafted archive could
    cause Read to allocate unbounded amounts of memory, potentially causing resource exhaustion or panics.
    After fix, Reader.Read limits the maximum size of header blocks to 1 MiB. (CVE-2022-2879)

  - Requests forwarded by ReverseProxy include the raw query parameters from the inbound request, including
    unparsable parameters rejected by net/http. This could permit query parameter smuggling when a Go proxy
    forwards a parameter with an unparsable value. After fix, ReverseProxy sanitizes the query parameters in
    the forwarded query when the outbound request's Form field is set after the ReverseProxy. Director
    function returns, indicating that the proxy has parsed the query parameters. Proxies which do not parse
    query parameters continue to forward the original query parameters unchanged. (CVE-2022-2880)

  - Programs which compile regular expressions from untrusted sources may be vulnerable to memory exhaustion
    or denial of service. The parsed regexp representation is linear in the size of the input, but in some
    cases the constant factor can be as high as 40,000, making relatively small regexps consume much larger
    amounts of memory. After fix, each regexp being parsed is limited to a 256 MB memory footprint. Regular
    expressions whose representation would use more space than that are rejected. Normal use of regular
    expressions is unaffected. (CVE-2022-41715)

  - An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

  - A maliciously crafted HTTP/2 stream could cause excessive CPU consumption in the HPACK decoder, sufficient
    to cause a denial of service from a small number of small requests. (CVE-2022-41723)

  - Large handshake records may cause panics in crypto/tls. Both clients and servers may send large TLS
    handshake records which cause servers and clients, respectively, to panic when attempting to construct
    responses. This affects all TLS 1.3 clients, TLS 1.2 clients which explicitly enable session resumption
    (by setting Config.ClientSessionCache to a non-nil value), and TLS 1.3 servers which request client
    certificates (by setting Config.ClientAuth >= RequestClientCert). (CVE-2022-41724)

  - A denial of service is possible from excessive resource consumption in net/http and mime/multipart.
    Multipart form parsing with mime/multipart.Reader.ReadForm can consume largely unlimited amounts of memory
    and disk files. This also affects form parsing in the net/http package with the Request methods FormFile,
    FormValue, ParseMultipartForm, and PostFormValue. ReadForm takes a maxMemory parameter, and is documented
    as storing up to maxMemory bytes +10MB (reserved for non-file parts) in memory. File parts which cannot
    be stored in memory are stored on disk in temporary files. The unconfigurable 10MB reserved for non-file
    parts is excessively large and can potentially open a denial of service vector on its own. However,
    ReadForm did not properly account for all memory consumed by a parsed form, such as map entry overhead,
    part names, and MIME headers, permitting a maliciously crafted form to consume well over 10MB. In
    addition, ReadForm contained no limit on the number of disk files created, permitting a relatively small
    request body to create a large number of disk temporary files. With fix, ReadForm now properly accounts
    for various forms of memory overhead, and should now stay within its documented limit of 10MB + maxMemory
    bytes of memory consumption. Users should still be aware that this limit is high and may still be
    hazardous. In addition, ReadForm now creates at most one on-disk temporary file, combining multiple form
    parts into a single temporary file. The mime/multipart.File interface type's documentation states, If
    stored on disk, the File's underlying concrete type will be an *os.File.. This is no longer the case when
    a form contains more than one file part, due to this coalescing of parts into a single file. The previous
    behavior of using distinct files for each form part may be reenabled with the environment variable
    GODEBUG=multipartfiles=distinct. Users should be aware that multipart.ReadForm and the http.Request
    methods that call it do not limit the amount of disk consumed by temporary files. Callers can limit the
    size of form data with http.MaxBytesReader. (CVE-2022-41725)

  - HTTP and MIME header parsing can allocate large amounts of memory, even when parsing small inputs,
    potentially leading to a denial of service. Certain unusual patterns of input data can cause the common
    function used to parse HTTP and MIME headers to allocate substantially more memory than required to hold
    the parsed headers. An attacker can exploit this behavior to cause an HTTP server to allocate large
    amounts of memory from a small request, potentially leading to memory exhaustion and a denial of service.
    With fix, header parsing now correctly allocates only the memory required to hold parsed headers.
    (CVE-2023-24534)

  - Multipart form parsing can consume large amounts of CPU and memory when processing form inputs containing
    very large numbers of parts. This stems from several causes: 1. mime/multipart.Reader.ReadForm limits the
    total memory a parsed multipart form can consume. ReadForm can undercount the amount of memory consumed,
    leading it to accept larger inputs than intended. 2. Limiting total memory does not account for increased
    pressure on the garbage collector from large numbers of small allocations in forms with many parts. 3.
    ReadForm can allocate a large number of short-lived buffers, further increasing pressure on the garbage
    collector. The combination of these factors can permit an attacker to cause an program that parses
    multipart forms to consume large amounts of CPU and memory, potentially resulting in a denial of service.
    This affects programs that use mime/multipart.Reader.ReadForm, as well as form parsing in the net/http
    package with the Request methods FormFile, FormValue, ParseMultipartForm, and PostFormValue. With fix,
    ReadForm now does a better job of estimating the memory consumption of parsed forms, and performs many
    fewer short-lived allocations. In addition, the fixed mime/multipart.Reader imposes the following limits
    on the size of parsed forms: 1. Forms parsed with ReadForm may contain no more than 1000 parts. This limit
    may be adjusted with the environment variable GODEBUG=multipartmaxparts=. 2. Form parts parsed with
    NextPart and NextRawPart may contain no more than 10,000 header fields. In addition, forms parsed with
    ReadForm may contain no more than 10,000 header fields across all parts. This limit may be adjusted with
    the environment variable GODEBUG=multipartmaxheaders=. (CVE-2023-24536)

  - Calling any of the Parse functions on Go source code which contains //line directives with very large line
    numbers can cause an infinite loop due to integer overflow. (CVE-2023-24537)

  - Templates do not properly consider backticks (`) as Javascript string delimiters, and do not escape them
    as expected. Backticks are used, since ES6, for JS template literals. If a template contains a Go template
    action within a Javascript template literal, the contents of the action can be used to terminate the
    literal, injecting arbitrary Javascript code into the Go template. As ES6 template literals are rather
    complex, and themselves can do string interpolation, the decision was made to simply disallow Go template
    actions from being used inside of them (e.g. var a = {{.}}), since there is no obviously safe way to
    allow this behavior. This takes the same approach as github.com/google/safehtml. With fix, Template.Parse
    returns an Error when it encounters templates like this, with an ErrorCode of value 12. This ErrorCode is
    currently unexported, but will be exported in the release of Go 1.21. Users who rely on the previous
    behavior can re-enable it using the GODEBUG flag jstmpllitinterp=1, with the caveat that backticks will
    now be escaped. This should be used with caution. (CVE-2023-24538)

  - The go command may generate unexpected code at build time when using cgo. This may result in unexpected
    behavior when running a go program which uses cgo. This may occur when running an untrusted module which
    contains directories with newline characters in their names. Modules which are retrieved using the go
    command, i.e. via go get, are not affected (modules retrieved using GOPATH-mode, i.e. GO111MODULE=off,
    may be affected). (CVE-2023-29402)

  - On Unix platforms, the Go runtime does not behave differently when a binary is run with the setuid/setgid
    bits. This can be dangerous in certain cases, such as when dumping memory state, or assuming the status of
    standard i/o file descriptors. If a setuid/setgid binary is executed with standard I/O file descriptors
    closed, opening any files can result in unexpected content being read or written with elevated privileges.
    Similarly, if a setuid/setgid program is terminated, either via panic or signal, it may leak the contents
    of its registers. (CVE-2023-29403)

  - The go command may execute arbitrary code at build time when using cgo. This may occur when running go
    get on a malicious module, or when running any other command which builds untrusted code. This is can by
    triggered by linker flags, specified via a #cgo LDFLAGS directive. The arguments for a number of flags
    which are non-optional are incorrectly considered optional, allowing disallowed flags to be smuggled
    through the LDFLAGS sanitization. This affects usage of both the gc and gccgo compilers. (CVE-2023-29404)

  - The go command may execute arbitrary code at build time when using cgo. This may occur when running go
    get on a malicious module, or when running any other command which builds untrusted code. This is can by
    triggered by linker flags, specified via a #cgo LDFLAGS directive. Flags containing embedded spaces are
    mishandled, allowing disallowed flags to be smuggled through the LDFLAGS sanitization by including them in
    the argument of another flag. This only affects usage of the gccgo compiler. (CVE-2023-29405)

  - The HTTP/1 client does not fully validate the contents of the Host header. A maliciously crafted Host
    header can inject additional headers or entire requests. With fix, the HTTP/1 client now refuses to send
    requests containing an invalid Request.Host or Request.URL.Host value. (CVE-2023-29406)

  - Extremely large RSA keys in certificate chains can cause a client/server to expend significant CPU time
    verifying signatures. With fix, the size of RSA keys transmitted during handshakes is restricted to <=
    8192 bits. Based on a survey of publicly trusted RSA keys, there are currently only three certificates in
    circulation with keys larger than this, and all three appear to be test certificates that are not actively
    deployed. It is possible there are larger keys in use in private PKIs, but we target the web PKI, so
    causing breakage here in the interests of increasing the default safety of users of crypto/tls seems
    reasonable. (CVE-2023-29409)

  - The html/template package does not properly handle HTML-like  comment tokens, nor hashbang #! comment
    tokens, in <script> contexts. This may cause the template parser to improperly interpret the contents of
    <script> contexts, causing actions to be improperly escaped. This may be leveraged to perform an XSS
    attack. (CVE-2023-39318)

  - The html/template package does not apply the proper rules for handling occurrences of <script, <!--,
    and </script within JS literals in <script> contexts. This may cause the template parser to improperly
    consider script contexts to be terminated early, causing actions to be improperly escaped. This could be
    leveraged to perform an XSS attack. (CVE-2023-39319)

  - The go.mod toolchain directive, introduced in Go 1.21, can be leveraged to execute scripts and binaries
    relative to the root of the module when the go command was executed within the module. This applies to
    modules downloaded using the go command from the module proxy, as well as modules downloaded directly
    using VCS software. (CVE-2023-39320)

  - Processing an incomplete post-handshake message for a QUIC connection can cause a panic. (CVE-2023-39321)

  - QUIC connections do not set an upper bound on the amount of data buffered when reading post-handshake
    messages, allowing a malicious QUIC connection to cause unbounded memory growth. With fix, connections now
    consistently reject messages larger than 65KiB in size. (CVE-2023-39322)

  - Line directives (//line) can be used to bypass the restrictions on //go:cgo_ directives, allowing
    blocked linker and compiler flags to be passed during compilation. This can result in unexpected execution
    of arbitrary code when running go build. The line directive requires the absolute path of the file in
    which the directive lives, which makes exploiting this issue significantly more complex. (CVE-2023-39323)

  - A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive
    server resource consumption. While the total number of requests is bounded by the
    http2.Server.MaxConcurrentStreams setting, resetting an in-progress request allows the attacker to create
    a new request while the existing one is still executing. With the fix applied, HTTP/2 servers now bound
    the number of simultaneously executing handler goroutines to the stream concurrency limit
    (MaxConcurrentStreams). New requests arriving when at the limit (which can only happen after the client
    has reset an existing, in-flight request) will be queued until a handler exits. If the request queue grows
    too large, the server will terminate the connection. This issue is also fixed in golang.org/x/net/http2
    for users manually configuring HTTP/2. The default stream concurrency limit is 250 streams (requests) per
    HTTP/2 connection. This value may be adjusted using the golang.org/x/net/http2 package; see the
    Server.MaxConcurrentStreams setting and the ConfigureServer function. (CVE-2023-39325)

  - The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation
    can reset many streams quickly, as exploited in the wild in August through October 2023. (CVE-2023-44487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202311-09");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=873637");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=883783");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=894478");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903979");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=908255");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915555");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=916494");
  script_set_attribute(attribute:"solution", value:
"All Go users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-lang/go-1.20.10
          # emerge --ask --oneshot --verbose @golang-rebuild");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39320");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:go");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'dev-lang/go',
    'unaffected' : make_list("ge 1.20.10"),
    'vulnerable' : make_list("lt 1.20.10")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Go');
}
