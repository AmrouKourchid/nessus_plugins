#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232658);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2025-1920",
    "CVE-2025-2135",
    "CVE-2025-2136",
    "CVE-2025-2137",
    "CVE-2025-24201"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/03");

  script_name(english:"Microsoft Edge (Chromium) < 134.0.3124.66 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 134.0.3124.66. It is, therefore, affected
by multiple vulnerabilities as referenced in the March 12, 2025 advisory.

  - Out of bounds read in V8 in Google Chrome prior to 134.0.6998.88 allowed a remote attacker to perform out
    of bounds memory access via a crafted HTML page. (Chromium security severity: Medium) (CVE-2025-2137)

  - Use after free in Inspector in Google Chrome prior to 134.0.6998.88 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2025-2136)

  - Type Confusion in V8 in Google Chrome prior to 134.0.6998.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2025-1920,
    CVE-2025-2135)

  - An out-of-bounds write issue was addressed with improved checks to prevent unauthorized actions. This
    issue is fixed in visionOS 2.3.2, iOS 18.3.2 and iPadOS 18.3.2, macOS Sequoia 15.3.2, Safari 18.3.1.
    Maliciously crafted web content May be able to break out of Web Content sandbox. This is a supplementary
    fix for an attack that was blocked in iOS 17.2. (Apple is aware of a report that this issue May have been
    exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS
    before iOS 17.2.). (CVE-2025-24201)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#march-12-2025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9fba8c3");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-1920");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2135");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2136");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2137");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-24201");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 134.0.3124.66 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2136");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-2137");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  		{ 'fixed_version' : '134.0.3124.66' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
