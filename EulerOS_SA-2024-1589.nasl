#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195278);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2023-45289",
    "CVE-2023-45290",
    "CVE-2024-24783",
    "CVE-2024-24785"
  );

  script_name(english:"EulerOS 2.0 SP10 : golang (EulerOS-SA-2024-1589)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the golang packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - When following an HTTP redirect to a domain which is not a subdomain match or exact match of the initial
    domain, an http.Client does not forward sensitive headers such as 'Authorization' or 'Cookie'. For
    example, a redirect from foo.com to www.foo.com will forward the Authorization header, but a redirect to
    bar.com will not. A maliciously crafted HTTP redirect could cause sensitive headers to be unexpectedly
    forwarded. (CVE-2023-45289)

  - When parsing a multipart form (either explicitly with Request.ParseMultipartForm or implicitly with
    Request.FormValue, Request.PostFormValue, or Request.FormFile), limits on the total size of the parsed
    form were not applied to the memory consumed while reading a single form line. This permits a maliciously
    crafted input containing very long lines to cause allocation of arbitrarily large amounts of memory,
    potentially leading to memory exhaustion. With fix, the ParseMultipartForm function now correctly limits
    the maximum size of form lines. (CVE-2023-45290)

  - Verifying a certificate chain which contains a certificate with an unknown public key algorithm will cause
    Certificate.Verify to panic. This affects all crypto/tls clients, and servers that set Config.ClientAuth
    to VerifyClientCertIfGiven or RequireAndVerifyClientCert. The default behavior is for TLS servers to not
    verify client certificates. (CVE-2024-24783)

  - If errors returned from MarshalJSON methods contain user controlled data, they may be used to break the
    contextual auto-escaping behavior of the html/template package, allowing for subsequent actions to inject
    unexpected content into templates. (CVE-2024-24785)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1589
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c5d5788");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-24783");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang-help");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "golang-1.15.7-15.h26.r2.eulerosv2r10",
  "golang-devel-1.15.7-15.h26.r2.eulerosv2r10",
  "golang-help-1.15.7-15.h26.r2.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang");
}
