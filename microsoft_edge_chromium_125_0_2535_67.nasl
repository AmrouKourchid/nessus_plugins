#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202467);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2024-5157",
    "CVE-2024-5158",
    "CVE-2024-5159",
    "CVE-2024-5160",
    "CVE-2024-5274"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/18");

  script_name(english:"Microsoft Edge (Chromium) < 125.0.2535.67 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 125.0.2535.67. It is, therefore,
affected by multiple vulnerabilities as referenced in the May 16, 2024 advisory.

  - Use after free in Scheduling in Google Chrome prior to 125.0.6422.76 allowed a remote attacker to execute
    arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-5157)

  - Type Confusion in V8 in Google Chrome prior to 125.0.6422.76 allowed a remote attacker to potentially
    perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5158)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 125.0.6422.76 allowed a remote attacker to perform
    an out of bounds memory read via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5159)

  - Heap buffer overflow in Dawn in Google Chrome prior to 125.0.6422.76 allowed a remote attacker to perform
    an out of bounds memory write via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5160)

  - Type Confusion in V8. (CVE-2024-5274) 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#may-24-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c157b4b");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5157");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5158");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5159");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5160");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-5274");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 125.0.2535.67 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5274");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
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
if (extended)
	constraints = [  { 'fixed_version' : '124.0.2478.127' }  ]; 
else 
	constraints = [  { 'fixed_version' : '125.0.2535.67' }  ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
