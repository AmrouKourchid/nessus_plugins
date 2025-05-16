#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0055. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206834);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2016-3709",
    "CVE-2022-40303",
    "CVE-2022-40304",
    "CVE-2023-28484",
    "CVE-2023-29469"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : libxml2 Multiple Vulnerabilities (NS-SA-2024-0055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has libxml2 packages installed that are affected by multiple
vulnerabilities:

  - A Cross-site scripting (XSS) vulnerability was found in libxml2. A specially crafted input, when
    serialized and re-parsed by the libxml2 library, will result in a document with element attributes that
    did not exist in the original document. (CVE-2016-3709)

  - A flaw was found in libxml2. Parsing a XML document with the XML_PARSE_HUGE option enabled can result in
    an integer overflow because safety checks were missing in some functions. Also, the xmlParseEntityValue
    function didn't have any length limitation. (CVE-2022-40303)

  - A flaw was found in libxml2. When a reference cycle is detected in the XML entity cleanup function the XML
    entity data can be stored in a dictionary. In this case, the dictionary becomes corrupted resulting in
    logic errors, including memory errors like double free. (CVE-2022-40304)

  - A NULL pointer dereference vulnerability was found in libxml2. This issue occurs when parsing (invalid)
    XML schemas. (CVE-2023-28484)

  - A flaw was found in libxml2. This issue occurs when hashing empty strings which aren't null-terminated,
    xmlDictComputeFastKey could produce inconsistent results, which may lead to various logic or memory
    errors, including double free errors. (CVE-2023-29469)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0055");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-3709");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40303");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40304");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28484");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29469");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libxml2 packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40304");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'libxml2-2.9.7-16.el8_8.1',
    'libxml2-devel-2.9.7-16.el8_8.1',
    'python3-libxml2-2.9.7-16.el8_8.1'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxml2');
}
