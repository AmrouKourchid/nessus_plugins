#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192478);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2024-2625",
    "CVE-2024-2626",
    "CVE-2024-2627",
    "CVE-2024-2628",
    "CVE-2024-2629",
    "CVE-2024-2630",
    "CVE-2024-2631",
    "CVE-2024-26247",
    "CVE-2024-29057"
  );
  script_xref(name:"IAVA", value:"2024-A-0177-S");

  script_name(english:"Microsoft Edge (Chromium) < 123.0.2420.53 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 123.0.2420.53. It is, therefore, affected
by multiple vulnerabilities as referenced in the March 22, 2024 advisory.

  - Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability (CVE-2024-26247)

  - Object lifecycle issue in V8 in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    potentially exploit object corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-2625)

  - Out of bounds read in Swiftshader in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-2626)

  - Use after free in Canvas in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-2627)

  - Inappropriate implementation in Downloads in Google Chrome prior to 123.0.6312.58 allowed a remote
    attacker to perform UI spoofing via a crafted URL. (Chromium security severity: Medium) (CVE-2024-2628)

  - Incorrect security UI in iOS in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to perform
    UI spoofing via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-2629)

  - Inappropriate implementation in iOS in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-2630)

  - Inappropriate implementation in iOS in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    perform UI spoofing via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-2631)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2024-29057)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#march-22-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e927e481");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26247");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2625");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2626");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2627");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2628");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2629");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2630");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-2631");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-29057");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 123.0.2420.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2627");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/22");

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
if (!extended) {
	constraints = [
  		{ 'fixed_version' : '123.0.2420.53' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
