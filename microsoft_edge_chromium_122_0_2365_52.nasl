#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191023);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/05");

  script_cve_id(
    "CVE-2024-1669",
    "CVE-2024-1670",
    "CVE-2024-1671",
    "CVE-2024-1672",
    "CVE-2024-1673",
    "CVE-2024-1674",
    "CVE-2024-1675",
    "CVE-2024-1676",
    "CVE-2024-21423",
    "CVE-2024-26188",
    "CVE-2024-26192"
  );
  script_xref(name:"IAVA", value:"2024-A-0116-S");

  script_name(english:"Microsoft Edge (Chromium) < 122.0.2365.52 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 122.0.2365.52. It is, therefore, affected
by multiple vulnerabilities as referenced in the February 23, 2024 advisory.

  - Out of bounds memory access in Blink in Google Chrome prior to 122.0.6261.57 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-1669)

  - Use after free in Mojo in Google Chrome prior to 122.0.6261.57 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-1670)

  - Inappropriate implementation in Site Isolation in Google Chrome prior to 122.0.6261.57 allowed a remote
    attacker to bypass content security policy via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-1671)

  - Inappropriate implementation in Content Security Policy in Google Chrome prior to 122.0.6261.57 allowed a
    remote attacker to bypass content security policy via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2024-1672)

  - Use after free in Accessibility in Google Chrome prior to 122.0.6261.57 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via specific UI gestures.
    (Chromium security severity: Medium) (CVE-2024-1673)

  - Inappropriate implementation in Navigation in Google Chrome prior to 122.0.6261.57 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-1674)

  - Insufficient policy enforcement in Download in Google Chrome prior to 122.0.6261.57 allowed a remote
    attacker to bypass filesystem restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-1675)

  - Inappropriate implementation in Navigation in Google Chrome prior to 122.0.6261.57 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-1676)

  - Microsoft Edge (Chromium-based) Information Disclosure Vulnerability (CVE-2024-21423, CVE-2024-26192)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2024-26188)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#february-23-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?966a7e43");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1669");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1670");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1671");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1672");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1673");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1674");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1675");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1676");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21423");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26188");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26192");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 122.0.2365.52 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1675");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/26");

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
  		{ 'fixed_version' : '122.0.2365.52' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
