#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180040);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/18");

  script_cve_id(
    "CVE-2023-2312",
    "CVE-2023-4349",
    "CVE-2023-4350",
    "CVE-2023-4351",
    "CVE-2023-4352",
    "CVE-2023-4353",
    "CVE-2023-4354",
    "CVE-2023-4355",
    "CVE-2023-4356",
    "CVE-2023-4357",
    "CVE-2023-4358",
    "CVE-2023-4359",
    "CVE-2023-4360",
    "CVE-2023-4361",
    "CVE-2023-4362",
    "CVE-2023-4363",
    "CVE-2023-4364",
    "CVE-2023-4365",
    "CVE-2023-4366",
    "CVE-2023-4367",
    "CVE-2023-4368",
    "CVE-2023-36787",
    "CVE-2023-38158"
  );
  script_xref(name:"IAVA", value:"2023-A-0438-S");

  script_name(english:"Microsoft Edge (Chromium) < 116.0.1938.54 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 116.0.1938.54. It is, therefore, affected
by multiple vulnerabilities as referenced in the August 21, 2023 advisory.

  - Use after free in Offline in Google Chrome on Android prior to 116.0.5845.96 allowed a remote attacker who
    had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2312)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability (CVE-2023-36787)

  - Microsoft Edge (Chromium-based) Information Disclosure Vulnerability (CVE-2023-38158)

  - Use after free in Device Trust Connectors in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-4349)

  - Inappropriate implementation in Fullscreen in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to potentially spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-4350)

  - Use after free in Network in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who has
    elicited a browser shutdown to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-4351)

  - Type confusion in V8 in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4352)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4353)

  - Heap buffer overflow in Skia in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-4354)

  - Out of bounds memory access in V8 in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4355)

  - Use after free in Audio in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who has
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-4356)

  - Insufficient validation of untrusted input in XML in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to bypass file access restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4357)

  - Use after free in DNS in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4358)

  - Inappropriate implementation in App Launcher in Google Chrome on iOS prior to 116.0.5845.96 allowed a
    remote attacker to potentially spoof elements of the security UI via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-4359)

  - Inappropriate implementation in Color in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4360)

  - Inappropriate implementation in Autofill in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-4361)

  - Heap buffer overflow in Mojom IDL in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who
    had compromised the renderer process and gained control of a WebUI process to potentially exploit heap
    corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4362)

  - Inappropriate implementation in WebShare in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to spoof the contents of a dialog URL via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-4363)

  - Inappropriate implementation in Permission Prompts in Google Chrome prior to 116.0.5845.96 allowed a
    remote attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4364)

  - Inappropriate implementation in Fullscreen in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4365)

  - Use after free in Extensions in Google Chrome prior to 116.0.5845.96 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2023-4366)

  - Insufficient policy enforcement in Extensions API in Google Chrome prior to 116.0.5845.96 allowed an
    attacker who convinced a user to install a malicious extension to bypass an enterprise policy via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4367, CVE-2023-4368)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#august-21-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ae99e73");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2312");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36787");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38158");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4349");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4350");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4351");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4352");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4353");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4354");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4355");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4356");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4357");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4358");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4359");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4360");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4361");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4362");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4363");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4364");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4365");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4366");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4367");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4368");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 116.0.1938.54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4368");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/23");

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
if (extended) {
	constraints = [
  		{ 'fixed_version' : '116.0.1938.54' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '116.0.1938.54' }
	];
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
