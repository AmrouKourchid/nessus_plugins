#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198161);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-35204");
  script_xref(name:"IAVA", value:"2024-A-0316");

  script_name(english:"Veritas System Recovery Arbitrary File Creation (VTS24-005)");

  script_set_attribute(attribute:"synopsis", value:
"A back-up management application installed on the remote Windows host is affected by an abritrary file creation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Veritas System Recovery installed on the remote Windows host is 23.2 or prior. It is, therefore,
affected by an arbitrary file creation vulnerability. A local attacker could create a file in any arbitrary location 
within the filesystem. This includes protected directories, such as C:\Windows, C:\Windows\System32 and C:\Program 
Files. In addition, a local attacker could leverage this vulnerability to cause denial of service or to tamper with
important services.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/security/VTS24-005");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/article.100065391");
  # https://www.veritas.com/content/support/en_US/downloads/update.UPD860045
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25994526");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version after 23.2 or apply Hotfix 860045 per vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:system_recovery");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_system_recovery_win_installed.nbin");
  script_require_keys("installed_sw/Veritas System Recovery", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Veritas System Recovery', win_local:TRUE);

# Can't detect hotfix
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'max_version': '23.2.999999', 'fixed_display': 'Apply Hotfix 860045 per vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
