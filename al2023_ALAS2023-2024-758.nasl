#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-758.
##

include('compat.inc');

if (description)
{
  script_id(211373);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id(
    "CVE-2024-7264",
    "CVE-2024-45806",
    "CVE-2024-45808",
    "CVE-2024-45809",
    "CVE-2024-45810"
  );

  script_name(english:"Amazon Linux 2023 : ecs-service-connect-agent (ALAS2023-2024-758)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-758 advisory.

    Envoy is a cloud-native high-performance edge/middle/service proxy. A security vulnerability in Envoy
    allows external clients to manipulate Envoy headers, potentially leading to unauthorized access or other
    malicious actions within the mesh. This issue arises due to Envoy's default configuration of internal
    trust boundaries, which considers all RFC1918 private address ranges as internal. The default behavior for
    handling internal addresses in Envoy has been changed. Previously, RFC1918 IP addresses were automatically
    considered internal, even if the internal_address_config was empty.  The default configuration of Envoy
    will continue to trust internal addresses while in this release and it will not trust them by default in
    next release. If you have tooling such as probes on your private network which need to be treated as
    trusted (e.g. changing arbitrary x-envoy headers) please explicitly include those addresses or CIDR ranges
    into `internal_address_config`. Successful exploitation could allow attackers to bypass security controls,
    access sensitive data, or disrupt services within the mesh, like Istio. This issue has been addressed in
    versions 1.31.2, 1.30.6, 1.29.9, and 1.28.7. Users are advised to upgrade. There are no known workarounds
    for this vulnerability. (CVE-2024-45806)

    Envoy is a cloud-native high-performance edge/middle/service proxy. A vulnerability has been identified in
    Envoy that allows malicious attackers to inject unexpected content into access logs. This is achieved by
    exploiting the lack of validation for the `REQUESTED_SERVER_NAME` field for access loggers. This issue has
    been addressed in versions 1.31.2, 1.30.6, 1.29.9, and 1.28.7. Users are advised to upgrade. There are no
    known workarounds for this vulnerability. (CVE-2024-45808)

    Envoy is a cloud-native high-performance edge/middle/service proxy. Jwt filter will lead to an Envoy crash
    when clear route cache with remote JWKs. In the following case: 1. remote JWKs are used, which requires
    async header processing; 2. clear_route_cache is enabled on the provider; 3. header operations are enabled
    in JWT filter, e.g. header to claims feature; 4. the routing table is configured in a way that the JWT
    header operations modify requests to not match any route. When these conditions are met, a crash is
    triggered in the upstream code due to nullptr reference conversion from route(). The root cause is the
    ordering of continueDecoding and clearRouteCache. This issue has been addressed in versions 1.31.2,
    1.30.6, and 1.29.9. Users are advised to upgrade. There are no known workarounds for this vulnerability.
    (CVE-2024-45809)

    Envoy is a cloud-native high-performance edge/middle/service proxy. Envoy will crash when the http async
    client is handling `sendLocalReply` under some circumstance, e.g., websocket upgrade, and requests
    mirroring. The http async client will crash during the `sendLocalReply()` in http async client, one reason
    is http async client is duplicating the status code, another one is the destroy of router is called at the
    destructor of the async stream, while the stream is deferred deleted at first. There will be problems that
    the stream decoder is destroyed but its reference is called in `router.onDestroy()`, causing segment
    fault. This will impact ext_authz if the `upgrade` and `connection` header are allowed, and request
    mirrorring. This issue has been addressed in versions 1.31.2, 1.30.6, 1.29.9, and 1.28.7. Users are
    advised to upgrade. There are no known workarounds for this vulnerability. (CVE-2024-45810)

    libcurl's ASN1 parser code has the `GTime2str()` function, used for parsing anASN.1 Generalized Time
    field. If given an syntactically incorrect field, theparser might end up using -1 for the length of the
    *time fraction*, leading toa `strlen()` getting performed on a pointer to a heap buffer area that is
    not(purposely) null terminated.

    This flaw most likely leads to a crash, but can also lead to heap contentsgetting returned to the
    application when[CURLINFO_CERTINFO](https://curl.se/libcurl/c/CURLINFO_CERTINFO.html) is used.
    (CVE-2024-7264)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-758.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45806.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45808.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45809.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45810.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-7264.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update ecs-service-connect-agent --releasever 2023.6.20241111' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45808");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

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
    {'reference':'ecs-service-connect-agent-v1.29.9.0-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ecs-service-connect-agent-v1.29.9.0-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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