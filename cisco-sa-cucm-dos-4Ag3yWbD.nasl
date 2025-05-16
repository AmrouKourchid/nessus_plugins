#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182581);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id("CVE-2023-20116");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe43377");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-dos-4Ag3yWbD");
  script_xref(name:"IAVA", value:"2023-A-0432");

  script_name(english:"Cisco Unified Communications Manager DoS (cisco-sa-cucm-dos-4Ag3yWbD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager installed on the remote host is prior to 12.5(1)SU8 or is version
14 prior to 14SU3. It is, therefore, affected by a denial-of-service vulnerability. Due to insufficient validation of
user-supplied input to the web UI of the Self Care Portal, an authenticated remote attacker can send a malicious HTTP
request causing a DoS condition on the affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-dos-4Ag3yWbD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?882ed3ad");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe43377");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe43377");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20116");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

var fix;
if (product_info.version =~ "^14\.")
  fix = '14SU3';
else
  fix = '12.5(1)SU8';

var vuln_ranges = [
    # 12.5(1)SU8 - https://software.cisco.com/download/home/286322286/type/286319236/release/12.5(1)SU8
    {'min_ver': '11.5', 'fix_ver': '12.5.1.18900.40'},
    # https://software.cisco.com/download/home/286328117/type/286319236/release/14SU3
    {'min_ver': '14.0', 'fix_ver': '14.0.1.13900.155'}
];


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'fix'      , fix,
  'bug_id'   , 'CSCwe43377',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);

