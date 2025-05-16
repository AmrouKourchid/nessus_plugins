#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205222);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/30");

  script_cve_id(
    "CVE-2024-7532",
    "CVE-2024-7533",
    "CVE-2024-7534",
    "CVE-2024-7535",
    "CVE-2024-7536",
    "CVE-2024-7550",
    "CVE-2024-38218",
    "CVE-2024-38219"
  );
  script_xref(name:"IAVA", value:"2024-A-0489-S");

  script_name(english:"Microsoft Edge (Chromium) < 127.0.2651.98 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 127.0.2651.98. It is, therefore, affected
by multiple vulnerabilities as referenced in the August 8, 2024 advisory.

  - Out of bounds memory access in ANGLE in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2024-7532)

  - Use after free in Sharing in Google Chrome on iOS prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7533)

  - Heap buffer overflow in Layout in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7534)

  - Inappropriate implementation in V8 in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7535)

  - Use after free in WebAudio in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7536)

  - Type Confusion in V8 in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-7550)

  - Microsoft Edge (HTML-based) Memory Corruption Vulnerability (CVE-2024-38218)

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability (CVE-2024-38219)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#august-8-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61fb8dc0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38218");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38219");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7532");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7533");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7534");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7535");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7536");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7550");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 127.0.2651.98 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7550");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/08");

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
  		{ 'fixed_version' : '127.0.2651.98' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
