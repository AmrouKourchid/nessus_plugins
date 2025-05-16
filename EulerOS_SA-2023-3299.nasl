#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189010);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/09");

  script_cve_id(
    "CVE-2023-29406",
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39323",
    "CVE-2023-39325",
    "CVE-2023-44487"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"EulerOS 2.0 SP9 : golang (EulerOS-SA-2023-3299)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the golang packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - The HTTP/1 client does not fully validate the contents of the Host header. A maliciously crafted Host
    header can inject additional headers or entire requests. With fix, the HTTP/1 client now refuses to send
    requests containing an invalid Request.Host or Request.URL.Host value. (CVE-2023-29406)

  - The html/template package does not properly handle HTML-like '' comment tokens, nor hashbang '#!' comment
    tokens, in <script> contexts. This may cause the template parser to improperly interpret the contents of
    <script> contexts, causing actions to be improperly escaped. This may be leveraged to perform an XSS
    attack. (CVE-2023-39318)

  - The html/template package does not apply the proper rules for handling occurrences of '<script', '<!--',
    and '</script' within JS literals in <script> contexts. This may cause the template parser to improperly
    consider script contexts to be terminated early, causing actions to be improperly escaped. This could be
    leveraged to perform an XSS attack. (CVE-2023-39319)

  - Line directives ('//line') can be used to bypass the restrictions on '//go:cgo_' directives, allowing
    blocked linker and compiler flags to be passed during compilation. This can result in unexpected execution
    of arbitrary code when running 'go build'. The line directive requires the absolute path of the file in
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

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f65eea63");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29406");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-39323");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang-help");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "golang-1.13.3-10.h50.eulerosv2r9",
  "golang-devel-1.13.3-10.h50.eulerosv2r9",
  "golang-help-1.13.3-10.h50.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
