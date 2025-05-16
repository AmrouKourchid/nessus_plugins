#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183055);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/09");

  script_cve_id(
    "CVE-2023-5218",
    "CVE-2023-5473",
    "CVE-2023-5474",
    "CVE-2023-5475",
    "CVE-2023-5476",
    "CVE-2023-5477",
    "CVE-2023-5478",
    "CVE-2023-5479",
    "CVE-2023-5481",
    "CVE-2023-5483",
    "CVE-2023-5484",
    "CVE-2023-5485",
    "CVE-2023-5486",
    "CVE-2023-5487",
    "CVE-2023-36559",
    "CVE-2023-36409"
  );
  script_xref(name:"IAVA", value:"2023-A-0566-S");
  script_xref(name:"IAVA", value:"2023-A-0578-S");

  script_name(english:"Microsoft Edge (Chromium) < 118.0.2088.46 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 118.0.2088.46. It is, therefore, affected
by multiple vulnerabilities as referenced in the October 13, 2023 advisory.

  - Use after free in Site Isolation in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-5218)

  - Use after free in Cast in Google Chrome prior to 118.0.5993.70 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Low) (CVE-2023-5473)

  - Heap buffer overflow in PDF in Google Chrome prior to 118.0.5993.70 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via a
    crafted PDF file. (Chromium security severity: Medium) (CVE-2023-5474)

  - Inappropriate implementation in DevTools in Google Chrome prior to 118.0.5993.70 allowed an attacker who
    convinced a user to install a malicious extension to bypass discretionary access control via a crafted
    Chrome Extension. (Chromium security severity: Medium) (CVE-2023-5475)

  - Use after free in Blink History in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5476)

  - Inappropriate implementation in Installer in Google Chrome prior to 118.0.5993.70 allowed a local attacker
    to bypass discretionary access control via a crafted command. (Chromium security severity: Low)
    (CVE-2023-5477)

  - Inappropriate implementation in Autofill in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5478)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 118.0.5993.70 allowed an attacker
    who convinced a user to install a malicious extension to bypass an enterprise policy via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-5479)

  - Inappropriate implementation in Downloads in Google Chrome prior to 118.0.5993.70 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5481)

  - Inappropriate implementation in Intents in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to bypass content security policy via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5483)

  - Inappropriate implementation in Navigation in Google Chrome prior to 118.0.5993.70 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5484)

  - Inappropriate implementation in Autofill in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to bypass autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5485)

  - Inappropriate implementation in Input in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    spoof security UI via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5486)

  - Inappropriate implementation in Fullscreen in Google Chrome prior to 118.0.5993.70 allowed an attacker who
    convinced a user to install a malicious extension to bypass navigation restrictions via a crafted Chrome
    Extension. (Chromium security severity: Medium) (CVE-2023-5487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#october-20-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2945f274");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36409");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 118.0.2088.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  		{ 'fixed_version' : '118.0.2088.46' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
