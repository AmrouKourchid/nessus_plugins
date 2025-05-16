#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178188);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id(
    "CVE-2023-29308",
    "CVE-2023-29309",
    "CVE-2023-29310",
    "CVE-2023-29311",
    "CVE-2023-29312",
    "CVE-2023-29313",
    "CVE-2023-29314",
    "CVE-2023-29315",
    "CVE-2023-29316",
    "CVE-2023-29317",
    "CVE-2023-29318",
    "CVE-2023-29319"
  );
  script_xref(name:"IAVA", value:"2023-A-0351-S");

  script_name(english:"Adobe InDesign < 17.4.2 / 18.0 < 18.4.0 Multiple Vulnerabilities (APSB23-38) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote macOS host is prior to 17.4.2, 18.4.0. It is, therefore, affected
by multiple vulnerabilities as referenced in the APSB23-38 advisory.

  - Adobe InDesign versions ID18.3 (and earlier) and ID17.4.1 (and earlier) are affected by an out-of-bounds
    write vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-29308)

  - Adobe InDesign versions ID18.3 (and earlier) and ID17.4.1 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2023-29309, CVE-2023-29310, CVE-2023-29311, CVE-2023-29312,
    CVE-2023-29313, CVE-2023-29314, CVE-2023-29315, CVE-2023-29316, CVE-2023-29317, CVE-2023-29318,
    CVE-2023-29319)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb23-38.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 17.4.2, 18.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29308");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'max_version' : '17.4.1', 'fixed_version' : '17.4.2', 'fixed_display' : 'ID17.4.2' },
  { 'min_version' : '18.0', 'max_version' : '18.3', 'fixed_version' : '18.4.0', 'fixed_display' : 'ID18.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
