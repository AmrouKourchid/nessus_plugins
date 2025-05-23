#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214405);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2024-38474",
    "CVE-2024-38475",
    "CVE-2024-38476",
    "CVE-2024-39884",
    "CVE-2024-40725"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/05/22");

  script_name(english:"EulerOS 2.0 SP8 : httpd (EulerOS-SA-2025-1122)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    A partial fix for CVE-2024-39884 in the core of Apache HTTP Server 2.4.61 ignores some use of the legacy
    content-type based configuration of handlers. 'AddType' and similar configuration, under some
    circumstances where files are requested indirectly, result in source code disclosure of local content. For
    example, PHP scripts may be served instead of interpreted.  Users are recommended to upgrade to version
    2.4.62, which fixes this issue.(CVE-2024-40725)

    A regression in the core of Apache HTTP Server 2.4.60 ignores some use of the legacy content-type based
    configuration of handlers. 'AddType' and similar configuration, under some circumstances where files
    are requested indirectly, result in source code disclosure of local content. For example, PHP scripts may
    be served instead of interpreted.  Users are recommended to upgrade to version 2.4.61, which fixes this
    issue.(CVE-2024-39884)

    Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows attacker to
    execute scripts in directories permitted by the configuration but not directly reachable by anyURL or
    source disclosure of scripts meant to only to be executed as CGI.  Users are recommended to upgrade to
    version 2.4.60, which fixes this issue.  Some RewriteRules that capture and substitute unsafely will now
    fail unless rewrite flag 'UnsafeAllow3F' is specified.(CVE-2024-38474)

    Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure,
    SSRF or local script execution viabackend applications whose response headers are malicious or
    exploitable.  Users are recommended to upgrade to version 2.4.60, which fixes this issue.(CVE-2024-38476)

    Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to
    map URLs to filesystem locations that arepermitted to be served by the server but are not
    intentionally/directly reachable by any URL, resulting in code execution or source code disclosure.
    Substitutions inserver context that use a backreferences or variables as the first segment of the
    substitution are affected. Some unsafe RewiteRules will be broken by this change and the rewrite flag
    'UnsafePrefixStat' can be used to opt back in once ensuring the substitution is appropriately
    constrained.(CVE-2024-38475)

Tenable has extracted the preceding description block directly from the EulerOS httpd security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1122
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7317bd81");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38476");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "httpd-2.4.34-8.h31.eulerosv2r8",
  "httpd-devel-2.4.34-8.h31.eulerosv2r8",
  "httpd-filesystem-2.4.34-8.h31.eulerosv2r8",
  "httpd-manual-2.4.34-8.h31.eulerosv2r8",
  "httpd-tools-2.4.34-8.h31.eulerosv2r8",
  "mod_session-2.4.34-8.h31.eulerosv2r8",
  "mod_ssl-2.4.34-8.h31.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
