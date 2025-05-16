#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186681);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/01");

  script_cve_id(
    "CVE-2023-6508",
    "CVE-2023-6509",
    "CVE-2023-6510",
    "CVE-2023-6511",
    "CVE-2023-6512",
    "CVE-2023-35618",
    "CVE-2023-36880",
    "CVE-2023-38174"
  );
  script_xref(name:"IAVA", value:"2023-A-0677-S");

  script_name(english:"Microsoft Edge (Chromium) < 120.0.2210.61 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 120.0.2210.61. It is, therefore, affected
by multiple vulnerabilities as referenced in the December 7, 2023 advisory.

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability (CVE-2023-35618)

  - Microsoft Edge (Chromium-based) Information Disclosure Vulnerability (CVE-2023-36880, CVE-2023-38174)

  - Use after free in Media Stream in Google Chrome prior to 120.0.6099.62 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6508)

  - Use after free in Side Panel Search in Google Chrome prior to 120.0.6099.62 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    UI interaction. (Chromium security severity: High) (CVE-2023-6509)

  - Use after free in Media Capture in Google Chrome prior to 120.0.6099.62 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    UI interaction. (Chromium security severity: Medium) (CVE-2023-6510)

  - Inappropriate implementation in Autofill in Google Chrome prior to 120.0.6099.62 allowed a remote attacker
    to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-6511)

  - Inappropriate implementation in Web Browser UI in Google Chrome prior to 120.0.6099.62 allowed a remote
    attacker to potentially spoof the contents of an iframe dialog context menu via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2023-6512)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#december-7-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f2952a2");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35618");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36880");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38174");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-6508");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-6509");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-6510");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-6511");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-6512");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 120.0.2210.61 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6510");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  		{ 'fixed_version' : '120.0.2210.61' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
