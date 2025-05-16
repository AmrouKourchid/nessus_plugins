#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180098);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/08");

  script_cve_id("CVE-2023-20111");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd77062");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-credentials-tkTO3h3");
  script_xref(name:"IAVA", value:"2023-A-0435-S");

  script_name(english:"Credential Information Disclosure Vulnerability(cisco-sa-ise-credentials-tkTO3h3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a vulnerability in the web-based 
management interface of Cisco Identity Services Engine (ISE) could allow an authenticated, remote attacker to access 
sensitive information. This vulnerability is due to the improper storage of sensitive information within the web-based 
management interface. An attacker could exploit this vulnerability by logging in to the web-based management interface 
and viewing hidden fields within the application. A successful exploit could allow the attacker to access sensitive 
information, including device entry credentials, that could aid the attacker in further attacks.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-credentials-tkTO3h3
  script_set_attribute(attribute:"see_also", value:"http://http://www.nessus.org/u?716eb592");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd77062");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd77062");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20111");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is own  ed by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'2.6', 'fix_ver':'2.7.0.356', required_patch:'10'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'8'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'7'},
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd77062',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
