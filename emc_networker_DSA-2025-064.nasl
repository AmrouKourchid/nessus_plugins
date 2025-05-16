#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214999);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2025-21107");
  script_xref(name:"IAVA", value:"2025-A-0077");

  script_name(english:"Dell EMC NetWorker Unquoted Search Path (DSA-2025-064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by unquoted search path or element vulnerability.");
  script_set_attribute(attribute:"description", value:
"Dell NetWorker, version(s) prior to 19.11.0.3, all versions of 19.10 & prior versions contain(s) an Unquoted Search 
Path or Element vulnerability. A low privileged attacker with local access could potentially exploit this vulnerability, 
leading to Code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000278811/dsa-2025-064-security-update-for-dell-networker-networker-virtual-edition-and-networker-management-console-multiple-component-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?539fd8bf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC NetWorker 19.11.0.3, 19.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21107");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_networker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'EMC NetWorker', win_local:TRUE);

if (app_info['Management Console Installed'] == FALSE)
  audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', app_info.version, app_info.path);

var constraints = [
  { 'max_version' : '19.5.0', 'fixed_version' : '19.11.0.3', 'fixed_display' : '19.11.0.3 / 19.12'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
