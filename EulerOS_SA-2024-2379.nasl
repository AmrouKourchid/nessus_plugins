#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207196);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id("CVE-2023-45803", "CVE-2024-37891");

  script_name(english:"EulerOS 2.0 SP9 : python-pip (EulerOS-SA-2024-2379)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-pip packages installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

    urllib3 is a user-friendly HTTP client library for Python. urllib3 previously wouldn't remove the HTTP
    request body when an HTTP redirect response using status 301, 302, or 303 after the request had its method
    changed from one that could accept a request body (like `POST`) to `GET` as is required by HTTP RFCs.
    Although this behavior is not specified in the section for redirects, it can be inferred by piecing
    together information from different sections and we have observed the behavior in other major HTTP client
    implementations like curl and web browsers. Because the vulnerability requires a previously trusted
    service to become compromised in order to have an impact on confidentiality we believe the exploitability
    of this vulnerability is low. Additionally, many users aren't putting sensitive data in HTTP request
    bodies, if this is the case then this vulnerability isn't exploitable. Both of the following conditions
    must be true to be affected by this vulnerability: 1. Using urllib3 and submitting sensitive information
    in the HTTP request body (such as form data or JSON) and 2. The origin service is compromised and starts
    redirecting using 301, 302, or 303 to a malicious peer or the redirected-to service becomes compromised.
    This issue has been addressed in versions 1.26.18 and 2.0.7 and users are advised to update to resolve
    this issue. Users unable to update should disable redirects for services that aren't expecting to respond
    with redirects with `redirects=False` and disable automatic redirects with `redirects=False` and handle
    301, 302, and 303 redirects manually by stripping the HTTP request body.(CVE-2023-45803)

    urllib3 is a user-friendly HTTP client library for Python. When using urllib3's proxy support with
    `ProxyManager`, the `Proxy-Authorization` header is only sent to the configured proxy, as expected.
    However, when sending HTTP requests *without* using urllib3's proxy support, it's possible to accidentally
    configure the `Proxy-Authorization` header even though it won't have any effect as the request is not
    using a forwarding proxy or a tunneling proxy. In those cases, urllib3 doesn't treat the `Proxy-
    Authorization` HTTP header as one carrying authentication material and thus doesn't strip the header on
    cross-origin redirects. Because this is a highly unlikely scenario, we believe the severity of this
    vulnerability is low for almost all users. Out of an abundance of caution urllib3 will automatically strip
    the `Proxy-Authorization` header during cross-origin redirects to avoid the small chance that users are
    doing this on accident. Users should use urllib3's proxy support or disable automatic redirects to achieve
    safe processing of the `Proxy-Authorization` header, but we still decided to strip the header by default
    in order to further protect users who aren't using the correct approach. We believe the number of usages
    affected by this advisory is low. It requires all of the following to be true to be exploited: 1. Setting
    the `Proxy-Authorization` header without using urllib3's built-in proxy support. 2. Not disabling HTTP
    redirects. 3. Either not using an HTTPS origin server or for the proxy or target origin to redirect to a
    malicious origin. Users are advised to update to either version 1.26.19 or version 2.2.2. Users unable to
    upgrade may use the `Proxy-Authorization` header with urllib3's `ProxyManager`, disable HTTP redirects
    using `redirects=False` when sending requests, or not user the `Proxy-Authorization` header as
    mitigations.(CVE-2024-37891)

Tenable has extracted the preceding description block directly from the EulerOS python-pip security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2379
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2f7fe5e");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pip packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-pip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "python-pip-wheel-18.0-13.h10.eulerosv2r9",
  "python3-pip-18.0-13.h10.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pip");
}
