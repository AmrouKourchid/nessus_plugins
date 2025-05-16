#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2025-941.
##

include('compat.inc');

if (description)
{
  script_id(234952);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id(
    "CVE-2025-2784",
    "CVE-2025-32050",
    "CVE-2025-32051",
    "CVE-2025-32052",
    "CVE-2025-32053",
    "CVE-2025-32906",
    "CVE-2025-32909",
    "CVE-2025-32910",
    "CVE-2025-32911",
    "CVE-2025-32912",
    "CVE-2025-32913"
  );

  script_name(english:"Amazon Linux 2023 : libsoup3, libsoup3-devel (ALAS2023-2025-941)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2025-941 advisory.

    A flaw was found in libsoup. The package is vulnerable to a heap buffer over-read when sniffing content
    via the skip_insight_whitespace() function. Libsoup clients may read one byte out-of-bounds in response to
    a crafted HTTP response by an HTTP server. (CVE-2025-2784)

    A flaw was found in libsoup. The libsoup append_param_quoted() function may contain an overflow bug
    resulting in a buffer under-read. (CVE-2025-32050)

    A flaw was found in libsoup. The libsoup soup_uri_decode_data_uri() function may crash when processing
    malformed data URI. This flaw allows an attacker to cause a denial of service (DoS). (CVE-2025-32051)

    A flaw was found in libsoup. A vulnerability in the sniff_unknown() function may lead to heap buffer over-
    read. (CVE-2025-32052)

    A flaw was found in libsoup. A vulnerability in sniff_feed_or_html() and skip_insignificant_space()
    functions may lead to a heap buffer over-read. (CVE-2025-32053)

    A flaw was found in libsoup, where the soup_headers_parse_request() function may be vulnerable to an out-
    of-bound read. This flaw allows a malicious user to use a specially crafted HTTP request to crash the HTTP
    server. (CVE-2025-32906)

    A flaw was found in libsoup. SoupContentSniffer may be vulnerable to a NULL pointer dereference in the
    sniff_mp4 function. The HTTP server may cause the libsoup client to crash. (CVE-2025-32909)

    A flaw was found in libsoup, where soup_auth_digest_authenticate() is vulnerable to a NULL pointer
    dereference. This issue may cause the libsoup client to crash. (CVE-2025-32910)

    libsoup: Double free on  soup_message_headers_get_content_disposition() through  soup-message-headers.c
    via params GHashTable value (CVE-2025-32911)

    A flaw was found in libsoup, where SoupAuthDigest is vulnerable to a NULL pointer dereference. The HTTP
    server may cause the libsoup client to crash. (CVE-2025-32912)

    A flaw was found in libsoup, where the soup_message_headers_get_content_disposition() function is
    vulnerable to a NULL pointer dereference. This flaw allows a malicious HTTP peer to crash a libsoup client
    or server that uses this function. (CVE-2025-32913)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2025-941.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-2784.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32050.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32051.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32052.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32053.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32906.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32909.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32910.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32911.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32912.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-32913.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update libsoup3 --releasever 2023.7.20250428' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsoup3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsoup3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsoup3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsoup3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsoup3-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libsoup3-3.6.5-47.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup3-3.6.5-47.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup3-debuginfo-3.6.5-47.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup3-debuginfo-3.6.5-47.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup3-debugsource-3.6.5-47.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup3-debugsource-3.6.5-47.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup3-devel-3.6.5-47.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup3-devel-3.6.5-47.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsoup3-doc-3.6.5-47.amzn2023', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsoup3 / libsoup3-debuginfo / libsoup3-debugsource / etc");
}
