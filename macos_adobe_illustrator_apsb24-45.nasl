#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205429);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id(
    "CVE-2024-34118",
    "CVE-2024-34133",
    "CVE-2024-34134",
    "CVE-2024-34135",
    "CVE-2024-34136",
    "CVE-2024-34137",
    "CVE-2024-34138"
  );
  script_xref(name:"IAVA", value:"2024-A-0477-S");

  script_name(english:"Adobe Illustrator < 27.9.5 / 28.0 < 28.6 Multiple Vulnerabilities (APSB24-45) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Illustrator instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator installed on the remote macOS host is prior to 27.9.5, 28.6. It is, therefore, affected
by multiple vulnerabilities as referenced in the APSB24-45 advisory.

  - Illustrator versions 28.5, 27.9.4 and earlier are affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2024-34133)

  - Illustrator versions 28.5, 27.9.4 and earlier are affected by an Improper Input Validation vulnerability
    that could lead to an application denial-of-service condition. An attacker could exploit this
    vulnerability to render the application unresponsive or terminate its execution. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2024-34118)

  - Illustrator versions 28.5, 27.9.4 and earlier are affected by an out-of-bounds read vulnerability that
    could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2024-34134, CVE-2024-34135)

  - Illustrator versions 28.5, 27.9.4 and earlier are affected by a NULL Pointer Dereference vulnerability
    that could lead to an application denial-of-service (DoS). An attacker could exploit this vulnerability to
    crash the application, resulting in a denial of service condition. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2024-34136, CVE-2024-34138)

  - Illustrator versions 28.5, 27.9.4 and earlier are affected by a NULL Pointer Dereference vulnerability
    that could lead to an application denial-of-service (DoS) condition. An attacker could exploit this
    vulnerability to crash the application, resulting in a DoS. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2024-34137)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb24-45.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator version 27.9.5, 28.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 369, 476, 787);

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_adobe_illustrator_installed.nbin");
  script_require_keys("installed_sw/Adobe Illustrator", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Illustrator');

var constraints = [
  { 'fixed_version' : '27.9.5' },
  { 'min_version' : '28.0', 'fixed_version' : '28.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
