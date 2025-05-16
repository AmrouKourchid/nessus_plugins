#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185896);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2023-47246");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/04");
  script_xref(name:"IAVA", value:"2023-A-0640-S");

  script_name(english:"SysAid Server < 23.3.36 Path Traversal");

  script_set_attribute(attribute:"synopsis", value:
"The inventory management server on the remote Windows host is affected by a path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SysAid Server installed on the remote host is prior to 23.3.36. It is, therefore, affected by a path
traversal vulnerability that leads to code execution after an attacker writes a file to the Tomcat webroot.
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91179b35");
  script_set_attribute(attribute:"see_also", value:"https://documentation.sysaid.com/docs/23336");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SysAid Server 23.3.36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sysaid:sysaid_on-premises");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sysaid_server_win_installed.nbin");
  script_require_keys("installed_sw/SysAid Server", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'SysAid Server');

var constraints = [{'fixed_version':'23.3.36'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);

