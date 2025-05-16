#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2023-1848.
##

include('compat.inc');

if (description)
{
  script_id(182699);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2022-41717",
    "CVE-2022-41722",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24532",
    "CVE-2023-24537",
    "CVE-2023-24538",
    "CVE-2023-24540",
    "CVE-2023-29400",
    "CVE-2023-29403",
    "CVE-2023-29404",
    "CVE-2023-29405",
    "CVE-2023-29406",
    "CVE-2023-29409",
    "CVE-2023-39319"
  );
  script_xref(name:"IAVB", value:"2023-B-0040-S");
  script_xref(name:"IAVB", value:"2023-B-0052-S");
  script_xref(name:"IAVB", value:"2023-B-0064-S");
  script_xref(name:"IAVB", value:"2023-B-0080-S");

  script_name(english:"Amazon Linux AMI : golang (ALAS-2023-1848)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of golang installed on the remote host is prior to 1.20.8-1.47. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2023-1848 advisory.

    2024-01-03: CVE-2023-24537 was added to this advisory.

    2024-01-03: CVE-2023-29400 was added to this advisory.

    2024-01-03: CVE-2023-24538 was added to this advisory.

    2024-01-03: CVE-2022-41722 was added to this advisory.

    2024-01-03: CVE-2022-41717 was added to this advisory.

    2024-01-03: CVE-2023-24540 was added to this advisory.

    2024-01-03: CVE-2022-41724 was added to this advisory.

    2024-01-03: CVE-2023-24532 was added to this advisory.

    2024-01-03: CVE-2023-39319 was added to this advisory.

    2024-01-03: CVE-2022-41725 was added to this advisory.

    2024-01-03: CVE-2023-29404 was added to this advisory.

    2024-01-03: CVE-2023-29405 was added to this advisory.

    An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

    The Go project has described this issue as follows:

    On Windows, the filepath.Clean function could transform an invalid path such as a/../c:/b into the valid
    path c:\b. This transformation of a relative (if invalid) path into an absolute path could enable a
    directory traversal attack. The filepath.Clean function will now transform this path into the relative
    (but still invalid) path .\c:\b. (CVE-2022-41722)

    Large handshake records may cause panics in crypto/tls. Both clients and servers may send large TLS
    handshake records which cause servers and clients, respectively, to panic when attempting to construct
    responses. This affects all TLS 1.3 clients, TLS 1.2 clients which explicitly enable session resumption
    (by setting Config.ClientSessionCache to a non-nil value), and TLS 1.3 servers which request client
    certificates (by setting Config.ClientAuth >= RequestClientCert). (CVE-2022-41724)

    Golang: net/http, mime/multipart: denial of service from excessive resource consumption
    (https://groups.google.com/g/golang-announce/c/V0aBFqaFs_E) (CVE-2022-41725)

    The ScalarMult and ScalarBaseMult methods of the P256 Curve may return an incorrect result if called with
    some specific unreduced scalars (a scalar larger than the order of the curve). This does not impact usages
    of crypto/ecdsa or crypto/ecdh. (CVE-2023-24532)

    Calling any of the Parse functions on Go source code which contains //line directives with very large line
    numbers can cause an infinite loop due to integer overflow. (CVE-2023-24537)

    Templates did not properly consider backticks (`) as Javascript string delimiters, and as such didnot
    escape them as expected. Backticks are used, since ES6, for JS template literals. If a templatecontained a
    Go template action within a Javascript template literal, the contents of the action couldbe used to
    terminate the literal, injecting arbitrary Javascript code into the Go template. (CVE-2023-24538)

    html/template: improper handling of JavaScript whitespace.

    Not all valid JavaScript whitespace characters were considered to be whitespace. Templates containing
    whitespace characters outside of the character set \t\n\f\r\u0020\u2028\u2029 in JavaScript contexts
    that also contain actions may not be properly sanitized during execution. (CVE-2023-24540)

    html/template: improper handling of empty HTML attributes.

    Templates containing actions in unquoted HTML attributes (e.g. attr={{.}}) executed with empty input
    could result in output that would have unexpected results when parsed due to HTML normalization rules.
    This may allow injection of arbitrary attributes into tags. (CVE-2023-29400)

    On Unix platforms, the Go runtime does not behave differently when a binary is run with the setuid/setgid
    bits. This can be dangerous in certain cases, such as when dumping memory state, or assuming the status of
    standard i/o file descriptors. If a setuid/setgid binary is executed with standard I/O file descriptors
    closed, opening any files can result in unexpected content being read or written with elevated privileges.
    Similarly, if a setuid/setgid program is terminated, either via panic or signal, it may leak the contents
    of its registers. (CVE-2023-29403)

    The go command may execute arbitrary code at build time when using cgo. This may occur when running go
    get on a malicious module, or when running any other command which builds untrusted code. This is can by
    triggered by linker flags, specified via a #cgo LDFLAGS directive. The arguments for a number of flags
    which are non-optional are incorrectly considered optional, allowing disallowed flags to be smuggled
    through the LDFLAGS sanitization. This affects usage of both the gc and gccgo compilers. (CVE-2023-29404)

    The go command may execute arbitrary code at build time when using cgo. This may occur when running go
    get on a malicious module, or when running any other command which builds untrusted code. This is can by
    triggered by linker flags, specified via a #cgo LDFLAGS directive. Flags containing embedded spaces are
    mishandled, allowing disallowed flags to be smuggled through the LDFLAGS sanitization by including them in
    the argument of another flag. This only affects usage of the gccgo compiler. (CVE-2023-29405)

    The HTTP/1 client does not fully validate the contents of the Host header. A maliciously crafted Host
    header can inject additional headers or entire requests. With fix, the HTTP/1 client now refuses to send
    requests containing an invalid Request.Host or Request.URL.Host value. (CVE-2023-29406)

    Extremely large RSA keys in certificate chains can cause a client/server to expend significant CPU time
    verifying signatures. With fix, the size of RSA keys transmitted during handshakes is restricted to <=
    8192 bits. Based on a survey of publicly trusted RSA keys, there are currently only three certificates in
    circulation with keys larger than this, and all three appear to be test certificates that are not actively
    deployed. It is possible there are larger keys in use in private PKIs, but we target the web PKI, so
    causing breakage here in the interests of increasing the default safety of users of crypto/tls seems
    reasonable. (CVE-2023-29409)

    The html/template package does not apply the proper rules for handling occurrences of <script, <!--,
    and </script within JS literals in <script> contexts. This may cause the template parser to improperly
    consider script contexts to be terminated early, causing actions to be improperly escaped. This could be
    leveraged to perform an XSS attack. (CVE-2023-39319)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2023-1848.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41717.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41722.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41724.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41725.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24532.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24537.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24538.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24540.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29400.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29403.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29404.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29405.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29406.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29409.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39319.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update golang' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'golang-1.20.8-1.47.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.20.8-1.47.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.20.8-1.47.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.20.8-1.47.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.20.8-1.47.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.20.8-1.47.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.20.8-1.47.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-shared-1.20.8-1.47.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.20.8-1.47.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.20.8-1.47.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang / golang-bin / golang-docs / etc");
}
