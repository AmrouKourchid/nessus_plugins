#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195160);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id("CVE-2024-33672");
  script_xref(name:"IAVA", value:"2024-A-0270-S");

  script_name(english:"Veritas NetBackup Arbitrary File Delete (VTS24-001)");

  script_set_attribute(attribute:"synopsis", value:
"A back-up management application installed on the remote host is affected by an abritrary file delete vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Veritas NetBackup application installed on the remote Windows host is prior to 9.1.0.1, 10.0.0.1, 10.1.1, prior
to 10.2.0.1, prior to 10.3.0.1 or prior to 10.4. It is, therefore, affected by an arbitrary file delete vulnerability.
An issue was discovered in Veritas NetBackup before 10.4. The Multi-Threaded Agent used in NetBackup can be leveraged
to perform arbitrary file deletion on protected files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/security/VTS24-001");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD649572");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD638863");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD126292");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD631427");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/downloads/update.UPD405441");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas NetBackup version 9.1.0.1, 10.0.0.1, 10.1.1, 10.2.0.1, 10.3.0.1, 10.4 or later or apply the appropriate EEB or hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-33672");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_netbackup_installed.nbin");
  script_require_keys("installed_sw/NetBackup");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NetBackup', win_local:TRUE);

var hotfixes = app_info.Patches;

var install_type = tolower(app_info['Install type']);
if ('client' >!< install_type && 'server' >!< install_type)
  audit(AUDIT_HOST_NOT, 'affected');

var constraints;
var fixed_version = '10.4';

if (!empty_or_null(pregmatch(pattern: "9\.1\.0($|[^0-9])", string:app_info.version)))
{
  if ('4047040' >< hotfixes) fixed_version = '9.1.0.1';
  constraints = [{ 'min_version': '8.3.0.2', 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4047040 per vendor advisory and upgrade to 9.1.0.1' }];
}
else if (!empty_or_null(pregmatch(pattern: "10\.0\.0($|[^0-9])", string:app_info.version)))
{
  if ('4078688' >< hotfixes) fixed_version = '10.0.0.1';
  constraints = [{ 'min_version': '10.0.0.0', 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4078688 per vendor advisory and upgrade to 10.0.0.1' }];
}
else if (!empty_or_null(pregmatch(pattern: "10\.1\.1", string:app_info.version)))
{
  if ('4102406' >< hotfixes) fixed_version = '10.1.1';
  constraints = [{ 'min_version': '10.1.1.0', 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4102406 per vendor advisory and upgrade to 10.1.1' }];
}
else if (!empty_or_null(pregmatch(pattern: "10\.2\.0\.1", string:app_info.version)))
{
  if ('4122719' >< hotfixes) fixed_version = '10.2.0.1';
  constraints = [{ 'min_version': '10.2.0.0', 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4122719 per vendor advisory and upgrade to 10.2.0.1'  }];
}
else if (!empty_or_null(pregmatch(pattern: "10\.3\.0\.1", string:app_info.version)))
{
  if ('4145974' >< hotfixes) fixed_version = '10.3.0.1';
  constraints = [{ 'min_version' : '10.3.0.0', 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4145974 per vendor advisory and upgrade to 10.3.0.1'  }];
}
else
{
  constraints = [{ 'min_version' : '8.3.0.2', 'fixed_version' : '10.4' }];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
