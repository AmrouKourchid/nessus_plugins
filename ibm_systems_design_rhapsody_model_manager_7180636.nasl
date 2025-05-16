#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214595);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-41779");
  script_xref(name:"IAVA", value:"2025-A-0056-S");

  script_name(english:"IBM Engineering Systems Design Rhapsody - Model Manager 7.0.2 < 7.0.2 iFix 32, 7.0.3 < 7.0.3 iFix 10 TOCTOU (7180636)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Engineering Systems Design Rhapsody - Model Manager installed on the remote
host is 7.0.2 prior to 7.0.2 ifix 32 or 7.0.3 prior to 7.0.3 ifix 10. It is, therefore, affected
by a Time-of-check Time-of-use (TOCTOU) vulnerability as referenced in the 7180636 advisory.

  - IBM Engineering Systems Design Rhapsody - Model Manager 7.0.2 and 7.0.3 could allow a remote attacker to bypass
    security restrictions, caused by a race condition. By sending a specially crafted request, an attacker could exploit
    this vulnerability to remotely execute code. (CVE-2024-41779)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7180636");
  script_set_attribute(attribute:"solution", value:
"Install 7.0.2 ifix 32 or 7.0.3 ifix 10 based upon the guidance specified in 7180636.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41779");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:engineering_systems_design_rhapsody_model_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_enum_products.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/IBM Engineering Systems Design Rhapsody - Model Manager");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

function doors_parser()
{
  var check_string = _FCT_ANON_ARGS[0];
  var new_check_string = '';
  check_string = pregmatch(pattern:"(\d+\.\d+\.\d+)( SR(\d+))?( i[fF]ix(\d+))?", string:check_string);
  if (len(check_string) > 1)
  {
    new_check_string = check_string[1];
    # I don't think we need the SR for anything and I only see SR1 as a valid SR
    #if (!empty_or_null(check_string[2]) && 'SR' >< check_string[2] && !empty_or_null(check_string[3]))
    #  new_check_string = new_check_string + '.' + check_string[3];
    #else
    #  new_check_string = new_check_string + '.0';
    if (!empty_or_null(check_string[4]) && 'iFix' >< check_string[4] && !empty_or_null(check_string[5]))
    {
      new_check_string = new_check_string + '.' + check_string[5];
    }
    else
    {
      new_check_string = new_check_string + '.0';
    }
  }
  return vcf::parse_version(use_custom:false, new_check_string);
}

vcf::set_custom_parse_version(func:@doors_parser);
var app_info = vcf::get_app_info(app:'IBM Engineering Systems Design Rhapsody - Model Manager', win_local:TRUE);
vcf::unset_custom_parse_version();

var constraints = [
  { 'min_version' : '7.0.2', 'fixed_version' : '7.0.2.032', 'fixed_display' : '7.0.2 iFix 32' },
  { 'min_version' : '7.0.3', 'fixed_version' : '7.0.3.010', 'fixed_display' : '7.0.3 iFix 10' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
