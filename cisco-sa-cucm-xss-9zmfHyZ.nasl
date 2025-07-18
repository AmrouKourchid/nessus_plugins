#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216527);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2024-20488");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi00276");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-xss-9zmfHyZ");
  script_xref(name:"IAVA", value:"2024-A-0517-S");

  script_name(english:"Cisco Unified Communications Manager XSS (cisco-sa-cucm-xss-9zmfHyZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager running on the report host is affected by
a cross-site scripting (XSS) vulnerability. Due to improper validation of suer-supplied input by the web-based
management interface, an unauthenticated, remote attacker can execute arbitrary script code in the context of the
affected interface or access sensitive data.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-xss-9zmfHyZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe40f154");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi00276");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi00276");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20488");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

var fix;
if (product_info['version'] =~ "^15\.")
  fix = '15SU1';
else
  fix = '14SU5';

var vuln_ranges = [
  # 14SU4a - vulnerable still, so increment it to 15000 following pattern of release numbers
  # https://software.cisco.com/download/home/286328117/type/286319236/release/14SU4a
  {'min_ver': '12.5', 'fix_ver': '14.0.1.15000.0'},
  # 15SU1 - https://software.cisco.com/download/home/286331940/type/286319236/release/15SU1
  {'min_ver': '15.0', 'fix_ver': '15.0.1.11900.23'}
];


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'fix'      , fix,
  'bug_id'   , 'CSCwi00276',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);

