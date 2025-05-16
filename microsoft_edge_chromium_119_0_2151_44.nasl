#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184320);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2023-5480",
    "CVE-2023-5482",
    "CVE-2023-5849",
    "CVE-2023-5850",
    "CVE-2023-5851",
    "CVE-2023-5852",
    "CVE-2023-5853",
    "CVE-2023-5854",
    "CVE-2023-5855",
    "CVE-2023-5856",
    "CVE-2023-5857",
    "CVE-2023-5858",
    "CVE-2023-5859",
    "CVE-2023-36022",
    "CVE-2023-36029",
    "CVE-2023-36034"
  );
  script_xref(name:"IAVA", value:"2023-A-0600-S");

  script_name(english:"Microsoft Edge (Chromium) < 118.0.2088.88 / 119.0.2151.44 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 118.0.2088.88 / 119.0.2151.44. It is,
therefore, affected by multiple vulnerabilities as referenced in the November 2, 2023 advisory.

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability (CVE-2023-36022, CVE-2023-36034)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2023-36029)

  - Inappropriate implementation in Payments in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to bypass XSS preventions via a malicious file. (Chromium security severity: High)
    (CVE-2023-5480)

  - Insufficient data validation in USB in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5482)

  - Integer overflow in USB in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-5849)

  - Incorrect security UI in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    perform domain spoofing via a crafted domain name. (Chromium security severity: Medium) (CVE-2023-5850)

  - Inappropriate implementation in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5851)

  - Use after free in Printing in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5852)

  - Incorrect security UI in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-5853)

  - Use after free in Profiles in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5854)

  - Use after free in Reading Mode in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5855)

  - Use after free in Side Panel in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-5856)

  - Inappropriate implementation in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to potentially execute arbitrary code via a malicious file. (Chromium security severity: Medium)
    (CVE-2023-5857)

  - Inappropriate implementation in WebApp Provider in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-5858)

  - Incorrect security UI in Picture In Picture in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to perform domain spoofing via a crafted local HTML page. (Chromium security severity: Low)
    (CVE-2023-5859)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#november-2-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1b5e0e7");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36022");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36029");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36034");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5480");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5482");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5849");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5850");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5851");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5852");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5853");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5854");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5855");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5856");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5857");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5858");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5859");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 118.0.2088.88 / 119.0.2151.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/03");

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
include('smb_hotfixes.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

if (hotfix_check_sp_range(win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (extended) {
	constraints = [
  		{ 'fixed_version' : '118.0.2088.88' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '119.0.2151.44' }
	];
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
