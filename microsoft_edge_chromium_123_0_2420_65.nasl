#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192634);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2024-2883",
    "CVE-2024-2885",
    "CVE-2024-2886",
    "CVE-2024-2887"
  );
  script_xref(name:"IAVA", value:"2024-A-0177-S");

  script_name(english:"Microsoft Edge (Chromium) < 122.0.2365.113 / 123.0.2420.65 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 122.0.2365.113 / 123.0.2420.65. It is,
therefore, affected by multiple vulnerabilities as referenced in the March 27, 2024 advisory.

  - Use after free in ANGLE in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical) (CVE-2024-2883)

  - Use after free in Dawn in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2885)

  - Use after free in WebCodecs in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to perform
    arbitrary read/write via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2886)

  - Type Confusion in WebAssembly in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to execute
    arbitrary code via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2887)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#march-27-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0feebe50");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2883");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2885");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2886");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2887");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 122.0.2365.113 / 123.0.2420.65 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2885");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/27");

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
if (extended) {
	constraints = [
  		{ 'fixed_version' : '122.0.2365.113' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '123.0.2420.65' }
	];
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
