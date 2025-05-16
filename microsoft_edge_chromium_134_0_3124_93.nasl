#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233369);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2025-2783");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/17");
  script_xref(name:"IAVA", value:"2025-A-0194-S");

  script_name(english:"Microsoft Edge (Chromium) < 134.0.3124.93 (CVE-2025-2783)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 134.0.3124.93. It is, therefore, affected
by a vulnerability as referenced in the March 26, 2025 advisory.

  - Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to
    134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium
    security severity: High) (CVE-2025-2783)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#march-26-2025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a263662");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2783");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 134.0.3124.93 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2783");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  		{ 'fixed_version' : '134.0.3124.93' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
