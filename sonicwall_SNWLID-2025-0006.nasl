#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234626);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2025-23008", "CVE-2025-23009", "CVE-2025-23010");
  script_xref(name:"IAVB", value:"2025-B-0059");

  script_name(english:"SonicWall NetExtender < 10.3.2 Multiple Vulnerabilities (SNWLID-2025-0006)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an multiple vulnerabilities vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SonicWall NetExtender installed on the remote host is prior to 10.3.2. It is, therefore,
affected by multiple vulnerabilities as referenced in the SNWLID-2025-0006 advisory.

  - An improper privilege management vulnerability in the SonicWall NetExtender Windows (32 and 64 bit) 
    client allows a low privileged attacker to modify configurations. (CVE-2025-23008)

  - A local privilege escalation vulnerability in SonicWall NetExtender Windows (32 and 64 bit) client which 
    allows an attacker to trigger an arbitrary file deletion. (CVE-2025-23009)

  - An Improper Link Resolution Before File Access ('Link Following') vulnerability in SonicWall NetExtender 
    Windows (32 and 64 bit) client which allows an attacker to manipulate file paths. (CVE-2025-23010)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0006");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23008");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonicwall:netextender");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_net_extender_win_installed.nbin");
  script_require_keys("installed_sw/SonicWall NetExtender");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match': {'os': 'windows'}}
  ],
  'checks': [
    {
      'product': {'name': 'SonicWall NetExtender', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'fixed_version':'10.3.2'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);

