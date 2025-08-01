#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191442);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_xref(name:"IAVA", value:"2024-A-0116-S");

  script_name(english:"Microsoft Edge (Chromium) < 122.0.2365.63 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 122.0.2365.63. It is, therefore, affected
by multiple vulnerabilities as referenced in the February 29, 2024 advisory.

  - Type Confusion in V8 in Google Chrome prior to 122.0.6261.94 allowed a remote attacker to potentially
    exploit object corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-1938)

  - Type Confusion in V8 in Google Chrome prior to 122.0.6261.94 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-1939)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#february-29-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2570be35");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1938");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1939");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 122.0.2365.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1939");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

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
get_kb_item_or_exit('SMB/Registry/Enumerated');

var product_name = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Server 2012" >< product_name)
  audit(AUDIT_OS_SP_NOT_VULN);

var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (!extended) {
	constraints = [
  		{ 'fixed_version' : '122.0.2365.63' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
