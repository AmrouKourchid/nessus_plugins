#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216852);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2025-22480");
  script_xref(name:"IAVA", value:"2025-A-0120");

  script_name(english:"Dell SupportAssist OS Recovery Symbolic Link Attack (DSA-2025-051)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a Dell SupportAssist OS Recovery install that is affected by a symbolic link attack
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Dell SupportAssist OS Recovery is affected by a symbolic
link attack vulnerability. A low-privileged attacker with local access could potentially exploit this vulnerability,
leading to arbitrary file deletion and Elevation of Privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000275712/dsa-2025-051");
  script_set_attribute(attribute:"solution", value:
"Update Dell SupportAssist OS Recovery version 5.5.13.1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22480");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:dell:supportassist_os_recovery");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_supportassist_os_recovery_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Dell SupportAssist OS Recovery");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_name = 'Dell SupportAssist OS Recovery';
var app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

var constraints = [
  { 'fixed_version':'5.5.13.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
