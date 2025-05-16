#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202055);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/03");

  script_cve_id(
    "CVE-2024-20781",
    "CVE-2024-20782",
    "CVE-2024-20783",
    "CVE-2024-20785",
    "CVE-2024-39392",
    "CVE-2024-39396",
    "CVE-2024-41836"
  );
  script_xref(name:"IAVA", value:"2024-A-0391-S");

  script_name(english:"Adobe InDesign < 18.5.3 / 19.0 < 19.4.0 Multiple Vulnerabilities (APSB24-48) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote macOS host is prior to 18.5.3, 19.4.0. It is, therefore, affected
by multiple vulnerabilities as referenced in the APSB24-48 advisory.

  - InDesign Desktop versions ID18.5.2, ID19.3 and earlier are affected by a Heap-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-39392)

  - InDesign Desktop versions ID19.3, ID18.5.2 and earlier are affected by a Heap-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-20781, CVE-2024-20783, CVE-2024-20785)

  - InDesign Desktop versions ID19.3, ID18.5.2 and earlier are affected by an out-of-bounds write
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-20782)

  - InDesign Desktop versions ID18.5.2, ID19.3 and earlier are affected by a NULL Pointer Dereference
    vulnerability that could lead to an application denial-of-service (DoS). An attacker could exploit this
    vulnerability to crash the application, resulting in a denial of service condition. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2024-41836)

  - InDesign Desktop versions ID18.5.2, ID19.3 and earlier are affected by an out-of-bounds read vulnerability
    that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2024-39396)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb24-48.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 18.5.3, 19.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_indesign_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe InDesign");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe InDesign');

var constraints = [
  { 'max_version' : '18.5.2', 'fixed_version' : '18.5.3', 'fixed_display' : 'ID18.5.3' },
  { 'min_version' : '19.0', 'max_version' : '19.3', 'fixed_version' : '19.4.0', 'fixed_display' : 'ID19.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
