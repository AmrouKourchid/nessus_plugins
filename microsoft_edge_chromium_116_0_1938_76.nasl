#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181128);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/06");

  script_cve_id(
    "CVE-2023-4761",
    "CVE-2023-4762",
    "CVE-2023-4763",
    "CVE-2023-4764"
  );
  script_xref(name:"IAVA", value:"2023-A-0457-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/27");

  script_name(english:"Microsoft Edge (Chromium) < 116.0.1938.76 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 116.0.1938.76. It is, therefore, affected
by multiple vulnerabilities as referenced in the September 7, 2023 advisory.

  - Out of bounds memory access in FedCM in Google Chrome prior to 116.0.5845.179 allowed a remote attacker
    who had compromised the renderer process to perform an out of bounds memory read via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-4761)

  - Type Confusion in V8 in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to execute
    arbitrary code via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4762)

  - Use after free in Networks in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4763)

  - Incorrect security UI in BFCache in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to
    spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4764)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#september-7-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c1fe891");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4761");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4762");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4763");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4764");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 116.0.1938.76 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4763");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  		{ 'fixed_version' : '116.0.1938.76' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
