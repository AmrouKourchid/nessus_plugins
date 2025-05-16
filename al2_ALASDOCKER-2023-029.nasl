#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASDOCKER-2023-029.
##

include('compat.inc');

if (description)
{
  script_id(180088);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24532",
    "CVE-2023-24534",
    "CVE-2023-24536",
    "CVE-2023-24537",
    "CVE-2023-24538",
    "CVE-2023-24539",
    "CVE-2023-24540",
    "CVE-2023-29400",
    "CVE-2023-29403",
    "CVE-2023-29406"
  );
  script_xref(name:"IAVB", value:"2023-B-0012-S");
  script_xref(name:"IAVB", value:"2023-B-0022-S");
  script_xref(name:"IAVB", value:"2023-B-0029-S");
  script_xref(name:"IAVB", value:"2023-B-0040-S");
  script_xref(name:"IAVB", value:"2023-B-0052-S");

  script_name(english:"Amazon Linux 2 : containerd (ALASDOCKER-2023-029)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of containerd installed on the remote host is prior to 1.6.19-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2DOCKER-2023-029 advisory.

    http2/hpack: avoid quadratic complexity in hpack decoding (CVE-2022-41723)

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

    HTTP and MIME header parsing could allocate large amounts of memory, even when parsing small inputs.

    Certain unusual patterns of input data could cause the common function used to parse HTTP and MIME headers
    to allocate substantially more memory than required to hold the parsed headers. An attacker can exploit
    this behavior to cause an HTTP server to allocate large amounts of memory from a small request,
    potentially leading to memory exhaustion and a denial of service. (CVE-2023-24534)

    Multipart form parsing can consume large amounts of CPU and memory when processing form inputs containing
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

    Calling any of the Parse functions on Go source code which contains //line directives with very large line
    numbers can cause an infinite loop due to integer overflow. (CVE-2023-24537)

    Templates did not properly consider backticks (`) as Javascript string delimiters, and as such didnot
    escape them as expected. Backticks are used, since ES6, for JS template literals. If a templatecontained a
    Go template action within a Javascript template literal, the contents of the action couldbe used to
    terminate the literal, injecting arbitrary Javascript code into the Go template. (CVE-2023-24538)

    html/template: improper sanitization of CSS values

    Angle brackets (<>) were not considered dangerous characters when inserted into CSS contexts. Templates
    containing multiple actions separated by a '/' character could result in unexpectedly closing the CSS
    context and allowing for injection of unexpected HMTL, if executed with untrusted input. (CVE-2023-24539)

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

    The HTTP/1 client does not fully validate the contents of the Host header. A maliciously crafted Host
    header can inject additional headers or entire requests. With fix, the HTTP/1 client now refuses to send
    requests containing an invalid Request.Host or Request.URL.Host value. (CVE-2023-29406)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASDOCKER-2023-029.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41723.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41724.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-41725.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24532.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24534.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24536.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24537.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24538.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24539.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-24540.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29400.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29403.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29406.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update containerd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24540");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-stress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'containerd-1.6.19-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-1.6.19-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-debuginfo-1.6.19-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-debuginfo-1.6.19-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-stress-1.6.19-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'containerd-stress-1.6.19-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-debuginfo / containerd-stress");
}
