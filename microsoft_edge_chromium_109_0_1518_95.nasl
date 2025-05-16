#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195171);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/09");

  script_cve_id("CVE-2023-0941");

  script_name(english:"Microsoft Edge (Chromium) < 109.0.1518.95 (CVE-2023-0941)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by a Use After Free vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge (Chromium) installed on the remote Windows host is prior to 109.0.1518.95. It is, therefore, 
affected by a use after free vulnerability in Prompts as referenced in the March 23, 2023 advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#march-23-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?484c9147");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0941");
  script_set_attribute(attribute:"see_also", value:"https://support.google.com/chrome/a/answer/7100626?hl=en");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 109.0.1518.95 or later. 

Please note that this a backported fix for Windows Server 2012 / 2012 R2, Windows 8 / 8.1 and Windows 7. Microsoft Edge 
(Chromium) branch 109.x is the final supported version for the aforementioned operating systems. If your operating 
system is Windows 10 or newer, it is recommended to update to Microsoft Edge (Chromium) 110.x or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0941");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/08");

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

if (hotfix_check_sp_range(win7:'0', win8:'0', win81:'0') <= 0) 
  audit(AUDIT_OS_SP_NOT_VULN);

var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var constraints = [ { 'fixed_version' : '109.0.1518.95' } ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
