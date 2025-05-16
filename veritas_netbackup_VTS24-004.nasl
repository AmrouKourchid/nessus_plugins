#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198144);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-34404");
  script_xref(name:"IAVA", value:"2024-A-0316");

  script_name(english:"Veritas NetBackup Improper Access Control (VTS24-004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Veritas NetBackup installed on the remote host is 9.1.0.1, 10.0, 10.0.0.1, 10.1, 10.1.1, 10.2,
10.2.0.1, 10.3, or 10.3.0.1. It is, therefore, affected by a vulnerability as referenced in the VTS24-004
advisory.

  - A vulnerability was discovered in the Alta Recovery Vault feature of Veritas NetBackup before 10.4. By
    design, only the cloud administrator should be able to disable the retention lock of Governance mode 
    images. This vulnerability allowed a NetBackup administrator to modify the expiration of backups under
    Governance mode (which could cause premature deletion). (CVE-2024-34404)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/security/VTS24-004");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/article.100065322");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD149656");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD715740");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD914005");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD947768");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD570820");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NetBackup version 10.4 or later, or apply the appropriate hotfix.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/30");

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

if (version == "9.1.0.1" && 'ET4055084' >!< patches)
  constraints = [{'equal': '9.1.0.1', 'fixed_display': 'Install hotfix ET4055084 or upgrade to 10.4'}];
else if (version == "10.0" && 'ET4069637' >!< patches)
  constraints = [{'equal': '10.0', 'fixed_display': 'Install hotfix ET4069637 or upgrade to 10.4'}];
else if (version == "10.0.0.1" && 'ET4079016' >!< patches)  
  constraints = [{'equal': '10.0.0.1', 'fixed_display': 'Install hotfix ET4079016 or upgrade to 10.4'}];
else if (version == "10.1" && 'ET4090334' >!< patches)
  constraints = [{'equal': '10.1', 'fixed_display': 'Install hotfix ET4090334 or upgrade to 10.4'}];
else if (version == "10.1.1" && 'ET4115990' >!< patches)
  constraints = [{'equal': '10.1.1', 'fixed_display': 'Install hotfix ET4115990 or upgrade to 10.4'}];
else if (version == "10.2" && 'ET4114925' >!< patches)
  constraints = [{'equal': '10.2', 'fixed_display': 'Install hotfix ET4114925 or upgrade to 10.4'}];
else if (version == "10.2.0.1" && 'ET4124797' >!< patches)
  constraints = [{'equal': '10.2.0.1', 'fixed_display': 'Install hotfix ET4124797 or upgrade to 10.4'}];
else if (version == "10.3" && 'ET4140861' >!< patches)
  constraints = [{'equal': '10.3', 'fixed_display': 'Install hotfix ET4140861 or upgrade to 10.4'}];
else if (version == "10.3.0.1" && 'ET4140863' >!< patches)
  constraints = [{'equal': '10.3.0.1', 'fixed_display': 'Install hotfix ET4140863 or upgrade to 10.4'}];
else
  audit(AUDIT_HOST_NOT, 'affected');

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
