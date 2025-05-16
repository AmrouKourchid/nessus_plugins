#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189605);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id(
    "CVE-2024-0804",
    "CVE-2024-0805",
    "CVE-2024-0806",
    "CVE-2024-0807",
    "CVE-2024-0808",
    "CVE-2024-0809",
    "CVE-2024-0810",
    "CVE-2024-0811",
    "CVE-2024-0812",
    "CVE-2024-0813",
    "CVE-2024-0814",
    "CVE-2024-21326",
    "CVE-2024-21336",
    "CVE-2024-21383",
    "CVE-2024-21385",
    "CVE-2024-21388"
  );
  script_xref(name:"IAVA", value:"2024-A-0060-S");
  script_xref(name:"IAVA", value:"2024-A-0253-S");

  script_name(english:"Microsoft Edge (Chromium) < 120.0.2210.160 / 121.0.2277.83 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 120.0.2210.160 / 121.0.2277.83. It is,
therefore, affected by multiple vulnerabilities as referenced in the January 26, 2024 advisory.

  - Insufficient policy enforcement in iOS Security UI in Google Chrome prior to 121.0.6167.85 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-0804)

  - Inappropriate implementation in Downloads in Google Chrome prior to 121.0.6167.85 allowed a remote
    attacker to perform domain spoofing via a crafted domain name. (Chromium security severity: Medium)
    (CVE-2024-0805)

  - Use after free in Passwords in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via specific UI interaction. (Chromium security severity: Medium)
    (CVE-2024-0806)

  - Use after free in Web Audio in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0807)

  - Integer underflow in WebUI in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via a malicious file. (Chromium security severity: High)
    (CVE-2024-0808)

  - Inappropriate implementation in Autofill in Google Chrome prior to 121.0.6167.85 allowed a remote attacker
    to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-0809)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 121.0.6167.85 allowed an attacker
    who convinced a user to install a malicious extension to leak cross-origin data via a crafted Chrome
    Extension. (Chromium security severity: Medium) (CVE-2024-0810)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 121.0.6167.85 allowed an attacker
    who convinced a user to install a malicious extension to leak cross-origin data via a crafted Chrome
    Extension. (Chromium security severity: Low) (CVE-2024-0811)

  - Inappropriate implementation in Accessibility in Google Chrome prior to 121.0.6167.85 allowed a remote
    attacker to potentially exploit object corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2024-0812)

  - Use after free in Reading Mode in Google Chrome prior to 121.0.6167.85 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific UI interaction.
    (Chromium security severity: Medium) (CVE-2024-0813)

  - Incorrect security UI in Payments in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-0814)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability (CVE-2024-21326, CVE-2024-21385,
    CVE-2024-21388)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2024-21336, CVE-2024-21383)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#january-26-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d9abc0d");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0804");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0805");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0806");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0807");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0808");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0809");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0810");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0811");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0812");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0813");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0814");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21326");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21336");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21383");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21385");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21388");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 120.0.2210.160 / 121.0.2277.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21326");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-0808");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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
if (extended) {
	constraints = [
  		{ 'fixed_version' : '120.0.2210.160' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '121.0.2277.83' }
	];
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
