#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209257);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/03");

  script_cve_id(
    "CVE-2024-9954",
    "CVE-2024-9955",
    "CVE-2024-9956",
    "CVE-2024-9957",
    "CVE-2024-9958",
    "CVE-2024-9959",
    "CVE-2024-9960",
    "CVE-2024-9961",
    "CVE-2024-9962",
    "CVE-2024-9963",
    "CVE-2024-9964",
    "CVE-2024-9965",
    "CVE-2024-9966",
    "CVE-2024-43566",
    "CVE-2024-43577",
    "CVE-2024-43578",
    "CVE-2024-43579",
    "CVE-2024-43580",
    "CVE-2024-43587",
    "CVE-2024-43595",
    "CVE-2024-43596",
    "CVE-2024-49023"
  );
  script_xref(name:"IAVA", value:"2024-A-0681-S");

  script_name(english:"Microsoft Edge (Chromium) < 130.0.2849.46 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 130.0.2849.46. It is, therefore, affected
by multiple vulnerabilities as referenced in the October 17, 2024 advisory.

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability (CVE-2024-43566, CVE-2024-43578,
    CVE-2024-43579, CVE-2024-43587, CVE-2024-43595, CVE-2024-43596, CVE-2024-49023)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2024-43577, CVE-2024-43580)

  - Use after free in AI in Google Chrome prior to 130.0.6723.58 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-9954)

  - Use after free in WebAuthentication in Google Chrome prior to 130.0.6723.58 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-9955)

  - Inappropriate implementation in WebAuthentication in Google Chrome on Android prior to 130.0.6723.58
    allowed a local attacker to perform privilege escalation via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2024-9956)

  - Use after free in UI in Google Chrome on iOS prior to 130.0.6723.58 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2024-9957)

  - Inappropriate implementation in PictureInPicture in Google Chrome prior to 130.0.6723.58 allowed a remote
    attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-9958)

  - Use after free in DevTools in Google Chrome prior to 130.0.6723.58 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: Medium) (CVE-2024-9959)

  - Use after free in Dawn in Google Chrome prior to 130.0.6723.58 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-9960)

  - Use after free in ParcelTracking in Google Chrome on iOS prior to 130.0.6723.58 allowed a remote attacker
    who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2024-9961)

  - Inappropriate implementation in Permissions in Google Chrome prior to 130.0.6723.58 allowed a remote
    attacker who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2024-9962)

  - Insufficient data validation in Downloads in Google Chrome prior to 130.0.6723.58 allowed a remote
    attacker who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2024-9963)

  - Inappropriate implementation in Payments in Google Chrome prior to 130.0.6723.58 allowed a remote attacker
    who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted Chrome
    Extension. (Chromium security severity: Low) (CVE-2024-9964)

  - Insufficient data validation in DevTools in Google Chrome on Windows prior to 130.0.6723.58 allowed a
    remote attacker who convinced a user to engage in specific UI gestures to execute arbitrary code via a
    crafted HTML page. (Chromium security severity: Low) (CVE-2024-9965)

  - Inappropriate implementation in Navigations in Google Chrome prior to 130.0.6723.58 allowed a remote
    attacker to bypass content security policy via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2024-9966)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#october-17-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32eca5fa");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9954");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9955");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9956");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9957");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9958");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9959");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9960");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9961");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9962");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9963");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9964");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9965");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-9966");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43566");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43577");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43578");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43579");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43580");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43587");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43595");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43596");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49023");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 130.0.2849.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9965");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-43566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  		{ 'fixed_version' : '130.0.2849.46' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
