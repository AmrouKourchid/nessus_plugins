#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204747);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2024-6988",
    "CVE-2024-6989",
    "CVE-2024-6991",
    "CVE-2024-6992",
    "CVE-2024-6993",
    "CVE-2024-6994",
    "CVE-2024-6995",
    "CVE-2024-6996",
    "CVE-2024-6997",
    "CVE-2024-6998",
    "CVE-2024-6999",
    "CVE-2024-7000",
    "CVE-2024-7001",
    "CVE-2024-7003",
    "CVE-2024-7004",
    "CVE-2024-7005",
    "CVE-2024-38103",
    "CVE-2024-39379"
  );
  script_xref(name:"IAVA", value:"2024-A-0452-S");

  script_name(english:"Microsoft Edge (Chromium) < 127.0.2651.74 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 127.0.2651.74. It is, therefore, affected
by multiple vulnerabilities as referenced in the July 25, 2024 advisory.

  - Microsoft Edge (Chromium-based) Information Disclosure Vulnerability (CVE-2024-38103)

  - Use after free in Downloads. (CVE-2024-6988)

  - Use after free in Loader. (CVE-2024-6989)

  - Use after free in Dawn. (CVE-2024-6991)

  - The vulnerability exists due to a boundary error when processing untrusted input in ANGLE. A remote
    attacker can create a specially crafted web page, trick the victim into visiting it, trigger out-of-bounds
    write and execute arbitrary code on the target system. (CVE-2024-6992)

  - The vulnerability exists due to inappropriate implementation in Canvas. A remote attacker can create a
    specially crafted web page, trick the victim into visiting it and gain unauthorized access to the system.
    (CVE-2024-6993)

  - Heap buffer overflow in Layout. (CVE-2024-6994)

  - Inappropriate implementation in Fullscreen. (CVE-2024-6995)

  - Race in Frames. (CVE-2024-6996)

  - Use after free in Tabs. (CVE-2024-6997)

  - Use after free in User Education. (CVE-2024-6998)

  - Inappropriate implementation in FedCM. (CVE-2024-6999, CVE-2024-7003)

  - Use after free in CSS. (CVE-2024-7000)

  - Inappropriate implementation in HTML. (CVE-2024-7001)

  - Insufficient validation of untrusted input in Safe Browsing. (CVE-2024-7004, CVE-2024-7005)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#july-25-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb6545b");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38103");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-39379");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6988");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6989");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6991");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6992");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6993");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6994");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6995");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6996");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6997");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6998");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6999");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7000");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7001");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7003");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7004");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7005");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 127.0.2651.74 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/25");

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
  		{ 'fixed_version' : '127.0.2651.74' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
