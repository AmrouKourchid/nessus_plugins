#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4743.
##

include('compat.inc');

if (description)
{
  script_id(180917);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/07");

  script_cve_id(
    "CVE-2019-12520",
    "CVE-2019-12521",
    "CVE-2019-12523",
    "CVE-2019-12524",
    "CVE-2019-12526",
    "CVE-2019-12528",
    "CVE-2019-12529",
    "CVE-2019-12854",
    "CVE-2019-18676",
    "CVE-2019-18677",
    "CVE-2019-18678",
    "CVE-2019-18679",
    "CVE-2019-18860",
    "CVE-2020-8449",
    "CVE-2020-8450",
    "CVE-2020-14058",
    "CVE-2020-15049",
    "CVE-2020-24606"
  );

  script_name(english:"Oracle Linux 8 : squid:4 (ELSA-2020-4743)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4743 advisory.

  - An issue was discovered in Squid before 4.10. It allows a crafted FTP server to trigger disclosure of
    sensitive information from heap memory, such as information associated with other users' sessions or non-
    Squid processes. (CVE-2019-12528)

  - An issue was discovered in Squid before 4.10. Due to incorrect buffer management, a remote client can
    cause a buffer overflow in a Squid instance acting as a reverse proxy. (CVE-2020-8450)

  - An issue was discovered in http/ContentLengthInterpreter.cc in Squid before 4.12 and 5.x before 5.0.3. A
    Request Smuggling and Poisoning attack can succeed against the HTTP cache. The client sends an HTTP
    request with a Content-Length header containing +\ - or an uncommon shell whitespace character prefix
    to the length field-value. (CVE-2020-15049)

  - Squid before 4.13 and 5.x before 5.0.4 allows a trusted peer to perform Denial of Service by consuming all
    available CPU cycles during handling of a crafted Cache Digest response message. This only occurs when
    cache_peer is used with the cache digests feature. The problem exists because peerDigestHandleReply()
    livelocking in peer_digest.cc mishandles EOF. (CVE-2020-24606)

  - An issue was discovered in Squid before 4.10. Due to incorrect input validation, it can interpret crafted
    HTTP requests in unexpected ways to access server resources prohibited by earlier security filters.
    (CVE-2020-8449)

  - An issue was discovered in Squid through 4.7. When Squid is parsing ESI, it keeps the ESI elements in
    ESIContext. ESIContext contains a buffer for holding a stack of ESIElements. When a new ESIElement is
    parsed, it is added via addStackElement. addStackElement has a check for the number of elements in this
    buffer, but it's off by 1, leading to a Heap Overflow of 1 element. The overflow is within the same
    structure so it can't affect adjacent memory blocks, and thus just leads to a crash while processing.
    (CVE-2019-12521)

  - An issue was discovered in Squid before 4.9. When handling a URN request, a corresponding HTTP request is
    made. This HTTP request doesn't go through the access checks that incoming HTTP requests go through. This
    causes all access checks to be bypassed and allows access to restricted HTTP servers, e.g., an attacker
    can connect to HTTP servers that only listen on localhost. (CVE-2019-12523)

  - An issue was discovered in Squid through 4.7. When handling requests from users, Squid checks its rules to
    see if the request should be denied. Squid by default comes with rules to block access to the Cache
    Manager, which serves detailed server information meant for the maintainer. This rule is implemented via
    url_regex. The handler for url_regex rules URL decodes an incoming request. This allows an attacker to
    encode their URL to bypass the url_regex check, and gain access to the blocked resource. (CVE-2019-12524)

  - An issue was discovered in Squid before 4.9. URN response handling in Squid suffers from a heap-based
    buffer overflow. When receiving data from a remote server in response to an URN request, Squid fails to
    ensure that the response can fit within the buffer. This leads to attacker controlled data overflowing in
    the heap. (CVE-2019-12526)

  - An issue was discovered in Squid 2.x through 2.7.STABLE9, 3.x through 3.5.28, and 4.x through 4.7. When
    Squid is configured to use Basic Authentication, the Proxy-Authorization header is parsed via uudecode.
    uudecode determines how many bytes will be decoded by iterating over the input and checking its table. The
    length is then used to start decoding the string. There are no checks to ensure that the length it
    calculates isn't greater than the input buffer. This leads to adjacent memory being decoded as well. An
    attacker would not be able to retrieve the decoded data unless the Squid maintainer had configured the
    display of usernames on error pages. (CVE-2019-12529)

  - Squid before 4.9, when certain web browsers are used, mishandles HTML in the host (aka hostname) parameter
    to cachemgr.cgi. (CVE-2019-18860)

  - An issue was discovered in Squid before 4.12 and 5.x before 5.0.3. Due to use of a potentially dangerous
    function, Squid and the default certificate validation helper are vulnerable to a Denial of Service when
    opening a TLS connection to an attacker-controlled server for HTTPS. This occurs because unrecognized
    error values are mapped to NULL, but later code expects that each error value is mapped to a valid error
    string. (CVE-2020-14058)

  - An issue was discovered in Squid through 4.7 and 5. When receiving a request, Squid checks its cache to
    see if it can serve up a response. It does this by making a MD5 hash of the absolute URL of the request.
    If found, it servers the request. The absolute URL can include the decoded UserInfo (username and
    password) for certain protocols. This decoded info is prepended to the domain. This allows an attacker to
    provide a username that has special characters to delimit the domain, and treat the rest of the URL as a
    path or query string. An attacker could first make a request to their domain using an encoded username,
    then when a request for the target domain comes in that decodes to the exact URL, it will serve the
    attacker's HTML instead of the real HTML. On Squid servers that also act as reverse proxies, this allows
    an attacker to gain access to features that only reverse proxies can use, such as ESI. (CVE-2019-12520)

  - Due to incorrect string termination, Squid cachemgr.cgi 4.0 through 4.7 may access unallocated memory. On
    systems with memory access protections, this can cause the CGI process to terminate unexpectedly,
    resulting in a denial of service for all clients using it. (CVE-2019-12854)

  - An issue was discovered in Squid 3.x and 4.x through 4.8. Due to incorrect input validation, there is a
    heap-based buffer overflow that can result in Denial of Service to all clients using the proxy. Severity
    is high due to this vulnerability occurring before normal security checks; any remote client that can
    reach the proxy port can trivially perform the attack via a crafted URI scheme. (CVE-2019-18676)

  - An issue was discovered in Squid 3.x and 4.x through 4.8 when the append_domain setting is used (because
    the appended characters do not properly interact with hostname length restrictions). Due to incorrect
    message processing, it can inappropriately redirect traffic to origins it should not be delivered to.
    (CVE-2019-18677)

  - An issue was discovered in Squid 3.x and 4.x through 4.8. It allows attackers to smuggle HTTP requests
    through frontend software to a Squid instance that splits the HTTP Request pipeline differently. The
    resulting Response messages corrupt caches (between a client and Squid) with attacker-controlled content
    at arbitrary URLs. Effects are isolated to software between the attacker client and Squid. There are no
    effects on Squid itself, nor on any upstream servers. The issue is related to a request header containing
    whitespace between a header name and a colon. (CVE-2019-18678)

  - An issue was discovered in Squid 2.x, 3.x, and 4.x through 4.8. Due to incorrect data management, it is
    vulnerable to information disclosure when processing HTTP Digest Authentication. Nonce tokens contain the
    raw byte value of a pointer that sits within heap memory allocation. This information reduces ASLR
    protections and may aid attackers isolating memory areas to target for remote code execution attacks.
    (CVE-2019-18679)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4743.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected libecap, libecap-devel and / or squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-12526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libecap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libecap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:squid");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/squid');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module squid:4');
if ('4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module squid:' + module_ver);

var appstreams = {
    'squid:4': [
      {'reference':'libecap-1.0.1-2.module+el8.3.0+7819+eb7d4ef6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libecap-devel-1.0.1-2.module+el8.3.0+7819+eb7d4ef6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'squid-4.11-3.module+el8.3.0+7819+eb7d4ef6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'libecap-1.0.1-2.module+el8.3.0+7819+eb7d4ef6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libecap-devel-1.0.1-2.module+el8.3.0+7819+eb7d4ef6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'squid-4.11-3.module+el8.3.0+7819+eb7d4ef6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module squid:4');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecap / libecap-devel / squid');
}
