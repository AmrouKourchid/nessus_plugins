#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-647.
##

include('compat.inc');

if (description)
{
  script_id(200911);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2024-23326",
    "CVE-2024-30255",
    "CVE-2024-32475",
    "CVE-2024-32974",
    "CVE-2024-32975",
    "CVE-2024-32976",
    "CVE-2024-34362",
    "CVE-2024-34363",
    "CVE-2024-34364"
  );

  script_name(english:"Amazon Linux 2023 : ecs-service-connect-agent (ALAS2023-2024-647)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-647 advisory.

    2024-07-17: CVE-2024-30255 was added to this advisory.

    Envoy is a cloud-native, open source edge and service proxy. A theoretical request smuggling vulnerability
    exists through Envoy if a server can be tricked into adding an upgrade header into a response. Per RFC
    https://www.rfc-editor.org/rfc/rfc7230#section-6.7 a server sends 101 when switching protocols. Envoy
    incorrectly accepts a 200 response from a server when requesting a protocol upgrade, but 200 does not
    indicate protocol switch. This opens up the possibility of request smuggling through Envoy if the server
    can be tricked into adding the upgrade header to the response. (CVE-2024-23326)

    Envoy is a cloud-native, open source edge and service proxy. The HTTP/2 protocol stack in Envoy versions
    prior to 1.29.3, 1.28.2, 1.27.4, and 1.26.8 are vulnerable to CPU exhaustion due to flood of CONTINUATION
    frames. Envoy's HTTP/2 codec allows the client to send an unlimited number of CONTINUATION frames even
    after exceeding Envoy's header map limits. This allows an attacker to send a sequence of CONTINUATION
    frames without the END_HEADERS bit set causing CPU utilization, consuming approximately 1 core per
    300Mbit/s of traffic and culminating in denial of service through CPU exhaustion. Users should upgrade to
    version 1.29.3, 1.28.2, 1.27.4, or 1.26.8 to mitigate the effects of the CONTINUATION flood. As a
    workaround, disable HTTP/2 protocol for downstream connections. (CVE-2024-30255)

    Envoy is a cloud-native, open source edge and service proxy. When an upstream TLS cluster is used with
    `auto_sni` enabled, a request containing a `host`/`:authority` header longer than 255 characters triggers
    an abnormal termination of Envoy process. Envoy does not gracefully handle an error when setting SNI for
    outbound TLS connection. The error can occur when Envoy attempts to use the `host`/`:authority` header
    value longer than 255 characters as SNI for outbound TLS connection. SNI length is limited to 255
    characters per the standard. Envoy always expects this operation to succeed and abnormally aborts the
    process when it fails. This vulnerability is fixed in 1.30.1, 1.29.4, 1.28.3, and 1.27.5. (CVE-2024-32475)

    Envoy is a cloud-native, open source edge and service proxy. A crash was observed in
    `EnvoyQuicServerStream::OnInitialHeadersComplete()` with following call stack. It is a use-after-free
    caused by QUICHE continuing push request headers after `StopReading()` being called on the stream. As
    after `StopReading()`, the HCM's `ActiveStream` might have already be destroyed and any up calls from
    QUICHE could potentially cause use after free. (CVE-2024-32974)

    Envoy is a cloud-native, open source edge and service proxy. There is a crash at
    `QuicheDataReader::PeekVarInt62Length()`. It is caused by integer underflow in the
    `QuicStreamSequencerBuffer::PeekRegion()` implementation. (CVE-2024-32975)

    Envoy is a cloud-native, open source edge and service proxy. Envoyproxy with a Brotli filter can get into
    an endless loop during decompression of Brotli data with extra input. (CVE-2024-32976)

    Envoy is a cloud-native, open source edge and service proxy. There is a use-after-free in
    `HttpConnectionManager` (HCM) with `EnvoyQuicServerStream` that can crash Envoy. An attacker can exploit
    this vulnerability by sending a request without `FIN`, then a `RESET_STREAM` frame, and then after
    receiving the response, closing the connection. (CVE-2024-34362)

    Envoy is a cloud-native, open source edge and service proxy. Due to how Envoy invoked the nlohmann JSON
    library, the library could throw an uncaught exception from downstream data if incomplete UTF-8 strings
    were serialized. The uncaught exception would cause Envoy to crash. (CVE-2024-34363)

    Envoy is a cloud-native, open source edge and service proxy. Envoy exposed an out-of-memory (OOM) vector
    from the mirror response, since async HTTP client will buffer the response with an unbounded buffer.
    (CVE-2024-34364)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-647.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23326.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-30255.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-32475.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-32974.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-32975.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-32976.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-34362.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-34363.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-34364.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update ecs-service-connect-agent --releasever 2023.5.20240624' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23326");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ecs-service-connect-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ecs-service-connect-agent-v1.29.5.0-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ecs-service-connect-agent-v1.29.5.0-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecs-service-connect-agent");
}
