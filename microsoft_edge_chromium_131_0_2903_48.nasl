#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211402);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/08");

  script_cve_id(
    "CVE-2024-11110",
    "CVE-2024-11111",
    "CVE-2024-11112",
    "CVE-2024-11113",
    "CVE-2024-11114",
    "CVE-2024-11115",
    "CVE-2024-11116",
    "CVE-2024-11117",
    "CVE-2024-49025"
  );
  script_xref(name:"IAVA", value:"2024-A-0753-S");

  script_name(english:"Microsoft Edge (Chromium) < 131.0.2903.48 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 131.0.2903.48. It is, therefore, affected
by multiple vulnerabilities as referenced in the November 14, 2024 advisory.

  - Inappropriate implementation in Extensions in Google Chrome prior to 131.0.6778.69 allowed a remote
    attacker to bypass site isolation via a crafted Chrome Extension. (Chromium security severity: High)
    (CVE-2024-11110)

  - Inappropriate implementation in Autofill in Google Chrome prior to 131.0.6778.69 allowed a remote attacker
    who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2024-11111)

  - Use after free in Media in Google Chrome on Windows prior to 131.0.6778.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-11112)

  - Use after free in Accessibility in Google Chrome prior to 131.0.6778.69 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2024-11113)

  - Inappropriate implementation in Views in Google Chrome on Windows prior to 131.0.6778.69 allowed a remote
    attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2024-11114)

  - Insufficient policy enforcement in Navigation in Google Chrome on iOS prior to 131.0.6778.69 allowed a
    remote attacker to perform privilege escalation via a series of UI gestures. (Chromium security severity:
    Medium) (CVE-2024-11115)

  - Inappropriate implementation in Blink in Google Chrome prior to 131.0.6778.69 allowed a remote attacker
    who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2024-11116)

  - Inappropriate implementation in FileSystem in Google Chrome prior to 131.0.6778.69 allowed a remote
    attacker to bypass filesystem restrictions via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2024-11117)

  - Microsoft Edge (Chromium-based) Information Disclosure Vulnerability (CVE-2024-49025)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#november-14-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9b9d7d8");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-11110");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-11111");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-11112");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-11113");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-11114");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-11115");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-11116");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-11117");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49025");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 131.0.2903.48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11115");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  		{ 'fixed_version' : '131.0.2903.48' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
