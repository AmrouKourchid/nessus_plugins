#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210588);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/11");
  script_xref(name:"IAVA", value:"2024-A-0704-S");

  script_name(english:"Veritas NetBackup Privilege escalation (VTS24-012)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Veritas NetBackup installed on the remote host is 9.1.0.1, 10.0, 10.0.0.1, 10.1, 10.1.1, 10.2,
10.2.0.1, 10.3, or 10.3.0.1. It is, therefore, affected by a vulnerability as referenced in the VTS24-012
advisory.

  - This attack requires the attacker to have write access to the root drive where NetBackup is installed, 
    allowing them to install a malicious DLL. If a user executes specific NetBackup commands or an attacker 
    uses social engineering techniques to impel the user to execute the commands, the malicious DLL could be 
    loaded, resulting in execution of the attacker’s code in the user’s security context. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/security/VTS24-012");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD644013");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD558217");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NetBackup version 10.5 or 10.4.01 and apply the appropriate hotfix or 10.3.01 and apply 
 the appropriate hotfix.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_netbackup_installed.nbin");
  script_require_keys("installed_sw/NetBackup", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NetBackup', win_local:TRUE);

# NetBackup server must be configured to use Veritas Alta Recovery Vault
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var hotfixes = app_info.Patches;

var install_type = tolower(app_info['Install type']);
if ('server' >!< install_type)
  audit(AUDIT_HOST_NOT, 'affected');

var version = app_info.version;
var patches = app_info.Patches;
var constraints = [];

if (version == "9.1.0.1" )
  constraints = [{'equal': '9.1.0.1', 'fixed_display': 'Upgrade to NetBackup Version 10.3.0.1 and apply hotfix ET4179305 and ET4179306'}];
else if (version == "10.0" )
  constraints = [{'equal': '10.0', 'fixed_display': 'Upgrade to NetBackup Version 10.3.0.1 and apply hotfix ET4179305 and ET4179306'}];
else if (version == "10.0.0.1" )  
  constraints = [{'equal': '10.0.0.1', 'fixed_display': 'Upgrade to NetBackup Version 10.3.0.1 and apply hotfix ET4179305 and ET4179306'}];
else if (version == "10.1" )
  constraints = [{'equal': '10.1', 'fixed_display': 'Upgrade to NetBackup Version 10.3.0.1 and apply hotfix ET4179305 and ET4179306'}];
else if (version == "10.1.1" )
  constraints = [{'equal': '10.1.1', 'fixed_display': 'Upgrade to NetBackup Version 10.3.0.1 and apply hotfix ET4179305 and ET4179306'}];
else if (version == "10.2")
  constraints = [{'equal': '10.2', 'fixed_display': 'Upgrade to NetBackup Version 10.3.0.1 and apply hotfix ET4179305 and ET4179306'}];
else if (version == "10.2.0.1" )
  constraints = [{'equal': '10.2.0.1', 'fixed_display': 'Upgrade to NetBackup Version 10.3.0.1 and apply hotfix ET4179305 and ET4179306'}];
else if (version == "10.3")
  constraints = [{'equal': '10.3', 'fixed_display': 'Upgrade to NetBackup Version 10.3.0.1 and apply hotfix ET4179305 and ET4179306'}];
else if (version == "10.3.0.1" && ('ET4179305' >!< patches || 'ET4179306' >!< patches)) 
  constraints = [{'equal': '10.3.0.1', 'fixed_display': 'Install hotfix ET4179305 and ET4179306 or upgrade to 10.4'}];
else if (version == "10.4" )
  constraints = [{'equal': '10.4', 'fixed_display': 'upgrade to 10.4.0.1 and apply hotfixes ET4177068 and ET4176358'}];
else if (version == "10.4.0.1" && ('ET4177068' >!< patches || 'ET4176358' >!< patches))
  constraints = [{'equal': '10.4.0.1', 'fixed_display': 'Install hotfixes ET4177068 and ET4176358 or upgrade to 10.5'}];
else
  audit(AUDIT_HOST_NOT, 'affected');

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
