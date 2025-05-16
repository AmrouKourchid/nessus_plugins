#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2025-968.
##

include('compat.inc');

if (description)
{
  script_id(235902);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2025-22871", "CVE-2025-29786", "CVE-2025-30204");
  script_xref(name:"IAVB", value:"2025-B-0048-S");

  script_name(english:"Amazon Linux 2023 : amazon-cloudwatch-agent (ALAS2023-2025-968)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2025-968 advisory.

    The net/http package accepted data in the chunked transfer encoding containing an invalid chunk-size line
    terminated by a bare LF. When used in conjunction with a server or proxy which incorrectly interprets a
    bare LF in a chunk extension as part of the extension, this could permit request smuggling.
    (CVE-2025-22871)

    Expr is an expression language and expression evaluation for Go. Prior to version 1.17.0, if the Expr
    expression parser is given an unbounded input string, it will attempt to compile the entire string and
    generate an Abstract Syntax Tree (AST) node for each part of the expression. In scenarios where input size
    isn't limited, a malicious or inadvertent extremely large expression can consume excessive memory as the
    parser builds a huge AST. This can ultimately lead to*excessive memory usage and an Out-Of-Memory (OOM)
    crash of the process. This issue is relatively uncommon and will only manifest when there are no
    restrictions on the input size, i.e. the expression length is allowed to grow arbitrarily large. In
    typical use cases where inputs are bounded or validated, this problem would not occur. The problem has
    been patched in the latest versions of the Expr library. The fix introduces compile-time limits on the
    number of AST nodes and memory usage during parsing, preventing any single expression from exhausting
    resources. Users should upgrade to Expr version 1.17.0 or later, as this release includes the new node
    budget and memory limit safeguards. Upgrading to v1.17.0 ensures that extremely deep or large expressions
    are detected and safely aborted during compilation, avoiding the OOM condition. For users who cannot
    immediately upgrade, the recommended workaround is to impose an input size restriction before parsing. In
    practice, this means validating or limiting the length of expression strings that your application will
    accept. For example, set a maximum allowable number of characters (or nodes) for any expression and reject
    or truncate inputs that exceed this limit. By ensuring no unbounded-length expression is ever fed into the
    parser, one can prevent the parser from constructing a pathologically large AST and avoid potential memory
    exhaustion. In short, pre-validate and cap input size as a safeguard in the absence of the patch.
    (CVE-2025-29786)

    golang-jwt is a Go implementation of JSON Web Tokens. Prior to5.2.2 and 4.5.2, the function
    parse.ParseUnverified splits (via a call to strings.Split) its argument (which is untrusted data) on
    periods. As a result, in the face of a malicious request whose Authorization header consists of Bearer
    followed by many period characters, a call to that function incurs allocations to the tune of O(n) bytes
    (where n stands for the length of the function's argument), with a constant factor of about 16. This issue
    is fixed in 5.2.2 and 4.5.2. (CVE-2025-30204)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2025-968.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-22871.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-29786.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-30204.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update amazon-cloudwatch-agent --releasever 2023.7.20250512' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22871");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-30204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:amazon-cloudwatch-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'amazon-cloudwatch-agent-1.300054.1-2.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'amazon-cloudwatch-agent-1.300054.1-2.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "amazon-cloudwatch-agent");
}
