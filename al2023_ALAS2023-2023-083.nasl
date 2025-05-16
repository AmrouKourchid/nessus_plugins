#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-083.
##

include('compat.inc');

if (description)
{
  script_id(173171);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2022-22576",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27779",
    "CVE-2022-27780",
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-30115",
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208",
    "CVE-2022-32221",
    "CVE-2022-35252",
    "CVE-2022-35260",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2022-43551",
    "CVE-2022-43552"
  );
  script_xref(name:"IAVA", value:"2022-A-0451-S");
  script_xref(name:"IAVA", value:"2023-A-0008-S");
  script_xref(name:"IAVA", value:"2022-A-0224-S");
  script_xref(name:"IAVA", value:"2022-A-0255-S");
  script_xref(name:"IAVA", value:"2022-A-0350-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Amazon Linux 2023 : curl, curl-minimal, libcurl (ALAS2023-2023-083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-083 advisory.

    2024-02-15: CVE-2022-27781 was added to this advisory.

    A vulnerability was found in curl. This security flaw allows reusing OAUTH2-authenticated connections
    without properly ensuring that the connection was authenticated with the same credentials set for this
    transfer. This issue leads to an authentication bypass, either by mistake or by a malicious actor.
    (CVE-2022-22576)

    A vulnerability was found in curl. This security flaw allows leaking credentials to other servers when it
    follows redirects from auth-protected HTTP(S) URLs to other protocols and port numbers. (CVE-2022-27774)

    A vulnerability was found in curl. This security flaw occurs due to errors in the logic where the config
    matching function did not take the IPv6 address zone id into account. This issue can lead to curl reusing
    the wrong connection when one transfer uses a zone id, and the subsequent transfer uses another.
    (CVE-2022-27775)

    A vulnerability was found in curl. This security flaw allows leak authentication or cookie header data on
    HTTP redirects to the same host but another port number. Sending the same set of headers to a server on a
    different port number is a problem for applications that pass on custom `Authorization:` or
    `Cookie:`headers. Those headers often contain privacy-sensitive information or data. (CVE-2022-27776)

    A vulnerability was found in curl. The issue occurs because curl wrongly allows HTTP cookies to be set for
    Top Level Domains (TLDs) if the hostname is provided with a trailing dot. This flaw allows arbitrary sites
    to set cookies that get sent to a different and unrelated site or domain by a malicious actor.
    (CVE-2022-27779)

    A vulnerability was found in curl. This issue occurs because the curl URL parser wrongly accepts percent-
    encoded URL separators like / when decoding the hostname part of a URL, making it a different URL using
    the wrong hostname when it is later retrieved. This flaw allows a malicious actor to make circumventing
    filters. (CVE-2022-27780)

    libcurl provides the `CURLOPT_CERTINFO` option to allow applications torequest details to be returned
    about a server's certificate chain.Due to an erroneous function, a malicious server could make libcurl
    built withNSS get stuck in a never-ending busy-loop when trying to retrieve thatinformation.
    (CVE-2022-27781)

    A vulnerability was found in curl. This issue occurs because curl can reuse a previously created
    connection even when a TLS or SSH-related option is changed that should have prohibited reuse. This flaw
    leads to an authentication bypass, either by mistake or by a malicious actor. (CVE-2022-27782)

    A vulnerability was found in curl. This issue occurs because when using its HTTP Strict Transport
    Security(HSTS) support, it can instruct curl to use HTTPS directly instead of using an insecure clear text
    HTTP step even when HTTP is provided in the URL. This flaw leads to a clear text transmission of sensitive
    information. (CVE-2022-30115)

    A vulnerability was found in curl. This issue occurs because a malicious server can serve excessive
    amounts of `Set-Cookie:` headers in an HTTP response to curl, which stores all of them. This flaw leads to
    a denial of service, either by mistake or by a malicious actor. (CVE-2022-32205)

    A vulnerability was found in curl. This issue occurs because the number of acceptable links in the
    decompression chain was unbounded, allowing a malicious server to insert a virtually unlimited number of
    compression steps. This flaw leads to a denial of service, either by mistake or by a malicious actor.
    (CVE-2022-32206)

    A vulnerability was found in curl. This issue occurs because when curl saves cookies, alt-svc, and HSTS
    data to local files, it makes the operation atomic by finalizing the process with a rename from a
    temporary name to the final target file name. This flaw leads to unpreserved file permissions, either by
    mistake or by a malicious actor. (CVE-2022-32207)

    A vulnerability was found in curl. This issue occurs because it mishandles message verification failures
    when curl does FTP transfers secured by krb5. This flaw makes it possible for a Man-in-the-middle attack
    to go unnoticed and allows data injection into the client. (CVE-2022-32208)

    A vulnerability was found in curl. The issue occurs when doing HTTP(S) transfers, where curl might
    erroneously use the read callback () to ask for data to send, even when the  option has been set if it
    previously used the same handle to issue a  request which used that callback. This flaw may surprise the
    application and cause it to misbehave and either send off the wrong data or use memory after free or
    similar in the subsequent  request. (CVE-2022-32221)

    A vulnerability found in curl. This security flaw happens when curl is used to retrieve and parse cookies
    from an HTTP(S) server, where it accepts cookies using control codes (byte values below 32), and also when
    cookies that contain such control codes are later sent back to an HTTP(S) server, possibly causing the
    server to return a 400 response. This issue effectively allows a sister site to deny service to siblings
    and cause a denial of service attack. (CVE-2022-35252)

    A vulnerability was found in curl. The issue occurs when curl is told to parse a `.netrc` file for
    credentials. If that file ends in a line with consecutive non-white space letters and no newline, curl
    could read past the end of the stack-based buffer, and if the read works, it can write a zero byte beyond
    its boundary. This issue, in most cases, causes a segfault or similar problem. A denial of service can
    occur if a malicious user can provide a custom netrc file to an application or otherwise affect its
    contents. (CVE-2022-35260)

    A vulnerability was found in curl. The issue occurs if curl is told to use an HTTP proxy for a transfer
    with a non-HTTP(S) URL. It sets up the connection to the remote server by issuing a `CONNECT` request to
    the proxy and then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP
    proxies often only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead
    return a non-200 response code to the client. Due to flaws in the error/cleanup handling, this could
    trigger a double-free issue in curl if using one of the following schemes in the URL for the transfer:
    `dict,` `gopher,` `gophers,` `ldap`, `ldaps`, `rtmp`, `rtmps`, `telnet.` (CVE-2022-42915)

    A vulnerability was found in curl. The issue occurs because curl's HSTS check can be bypassed to trick it
    to keep using HTTP. Using its HSTS support, it can instruct curl to use HTTPS directly instead of using an
    insecure clear-text HTTP step even when HTTP is provided in the URL. This mechanism can be bypassed if the
    hostname in the given URL uses IDN characters that get replaced with ASCII counterparts as part of the IDN
    conversion. Like using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full
    stop (U+002E) . (CVE-2022-42916)

    A vulnerability exists in curl <7.87.0 HSTS check that could be bypassed to trick it to keep using HTTP.
    Using its HSTS support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP
    step even when HTTP is provided in the URL. However, the HSTS mechanism could be bypassed if the host name
    in the given URL first uses IDN characters that get replaced to ASCII counterparts as part of the IDN
    conversion. Like using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full
    stop (U+002E) `.`. Then in a subsequent request, it does not detect the HSTS state and makes a clear text
    transfer. Because it would store the info IDN encoded but look for it IDN decoded. (CVE-2022-43551)

    A vulnerability was found in curl. In this issue, curl can be asked to tunnel all protocols virtually it
    supports through an HTTP proxy. HTTP proxies can deny these tunnel operations using an appropriate HTTP
    error response code. When getting denied to tunnel the specific SMB or TELNET protocols, curl can use a
    heap-allocated struct after it has been freed and shut down the code path in its transfer.
    (CVE-2022-43552)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-083.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22576.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27774.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27775.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27776.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27779.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27780.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27781.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-27782.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-30115.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32205.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32206.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32207.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32208.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32221.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-35252.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-35260.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42915.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42916.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-43551.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-43552.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update curl --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'curl-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-7.87.0-2.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / etc");
}
