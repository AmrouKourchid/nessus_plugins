#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, inc.
##

include('compat.inc');

if (description)
{
  script_id(179693);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/24");

  script_cve_id("CVE-2022-4894");
  script_xref(name:"IAVA", value:"2023-A-0400");
  script_xref(name:"HP", value:"HPSBPI03857");

  script_name(english:"HP Printer Software Elevation of Privilege (HPSBPI03857)");

  script_set_attribute(attribute:"synopsis", value:
"The remote target is potentially affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"Certain HP and Samsung Printer software packages may potentially be vulnerable to elevation of privilege due to 
Uncontrolled Search Path Element.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.hp.com/us-en/document/ish_8947379-8947403-16/hpsbpi03857
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c4c5682");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the HP LaserJet firmware referenced in the
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4894");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hp:laserjet_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_softwares.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');


function extract_version(version)
{
  version = pregmatch(pattern: "^V(\d+\.\d+)", string: version);
  if (empty_or_null(object: version ) || empty_or_null(object: version[1] ))
    return NULL;
  return version[1];
}

function get_app_info(product_list)
{
  var kb_base = 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/';
  var found = [], found_kb, found_ver, app_info;
  for (var product in product_list)
  {
    found_kb = get_kb_list(kb_base + product + '/*');
    if (empty_or_null(object: found_kb ))
      continue;
    var display_name = found_kb[kb_base + product + '/DisplayName'];
    var display_version = found_kb[kb_base + product + '/DisplayVersion'];
  
    if (empty_or_null(object: display_name ) || empty_or_null(object: display_version ))
      continue;
  
    found_ver = extract_version(version:display_version);
    if (empty_or_null(object: found_ver))
      continue;

    app_info.app = display_name;
    app_info.parsed_version = vcf::parse_version(found_ver);
    app_info.version = found_ver;
    app_info.display_version = found_ver;

    append_element(var:found, value:app_info);
    app_info = NULL;
  }
  return found;
}

var constraints = {
  'HP LaserJet MFP M72625-M72630': [{'fixed_version' : '1.06'}],
  'HP LaserJet MFP M436': [{'fixed_version' : '1.14'}],
  'HP LaserJet MFP M433': [{'fixed_version' : '1.04'}],
  'HP Laser MFP 432': [{'fixed_version' : '1.09'}],
  'HP LaserJet MFP M42523-M42625': [{'fixed_version' : '1.06'}],
  'HP LaserJet MFP M437-M443': [{'fixed_version' : '1.06'}],
  'HP Laser 103 107 108': [{'fixed_version' : '1.20'}],
  'HP Laser MFP 131 133 135-138': [{'fixed_version' : '1.20'}],
  'HP Color Laser 150': [{'fixed_version' : '1.20'}],
  'HP Color Laser MFP 178 179': [{'fixed_version' : '1.20'}],
  'HP Laser 1003-1008': [{'fixed_version' : '1.02'}],
  'HP Laser MFP 1136-1139 1188': [{'fixed_version' : '1.02'}]
};

var found = get_app_info(product_list:constraints);
var constraint;
if (!empty_or_null(object: found ))
{
  foreach (var app_info in found)
  {
    constraint = constraints[app_info.app];
    vcf::check_version_and_report(
      app_info:app_info,
      constraints:constraint,
      severity:SECURITY_WARNING
    );
  }
}
else
  audit(AUDIT_HOST_NOT, 'affected');
