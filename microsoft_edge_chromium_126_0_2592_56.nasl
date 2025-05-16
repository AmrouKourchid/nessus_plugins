#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200498);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2024-5830",
    "CVE-2024-5831",
    "CVE-2024-5832",
    "CVE-2024-5833",
    "CVE-2024-5834",
    "CVE-2024-5835",
    "CVE-2024-5836",
    "CVE-2024-5837",
    "CVE-2024-5838",
    "CVE-2024-5839",
    "CVE-2024-5840",
    "CVE-2024-5841",
    "CVE-2024-5842",
    "CVE-2024-5843",
    "CVE-2024-5844",
    "CVE-2024-5845",
    "CVE-2024-5846",
    "CVE-2024-5847",
    "CVE-2024-30058",
    "CVE-2024-38083"
  );
  script_xref(name:"IAVA", value:"2024-A-0342-S");
  script_xref(name:"IAVA", value:"2024-A-0371-S");

  script_name(english:"Microsoft Edge (Chromium) < 126.0.2592.56 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 126.0.2592.56. It is, therefore, affected
by multiple vulnerabilities as referenced in the June 13, 2024 advisory.

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2024-30058, CVE-2024-38083)

  - Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to perform an out
    of bounds memory write via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5830)

  - Use after free in Dawn in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5831,
    CVE-2024-5832)

  - Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-5833, CVE-2024-5837)

  - Inappropriate implementation in Dawn in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to
    execute arbitrary code via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5834)

  - Heap buffer overflow in Tab Groups in Google Chrome prior to 126.0.6478.54 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: High) (CVE-2024-5835)

  - Inappropriate Implementation in DevTools in Google Chrome prior to 126.0.6478.54 allowed an attacker who
    convinced a user to install a malicious extension to execute arbitrary code via a crafted Chrome
    Extension. (Chromium security severity: High) (CVE-2024-5836)

  - Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to perform out of
    bounds memory access via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5838)

  - Inappropriate Implementation in Memory Allocator in Google Chrome prior to 126.0.6478.54 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2024-5839)

  - Policy bypass in CORS in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to bypass
    discretionary access control via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-5840)

  - Use after free in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-5841)

  - Use after free in Browser UI in Google Chrome prior to 126.0.6478.54 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to perform an out of bounds memory read via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2024-5842)

  - Inappropriate implementation in Downloads in Google Chrome prior to 126.0.6478.54 allowed a remote
    attacker to obfuscate security UI via a malicious file. (Chromium security severity: Medium)
    (CVE-2024-5843)

  - Heap buffer overflow in Tab Strip in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-5844)

  - Use after free in Audio in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: Medium) (CVE-2024-5845)

  - Use after free in PDFium in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: Medium) (CVE-2024-5846,
    CVE-2024-5847)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#june-13-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a56865e");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30058");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38083");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5830");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5831");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5832");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5833");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5834");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5835");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5836");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5837");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5838");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5839");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5840");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5841");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5842");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5843");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5844");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5845");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5846");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5847");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 126.0.2592.56 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin", "smb_hotfixes.nasl");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
include('smb_hotfixes.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

if (hotfix_check_sp_range(win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (!extended) {
	constraints = [
  		{ 'fixed_version' : '126.0.2592.56' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
