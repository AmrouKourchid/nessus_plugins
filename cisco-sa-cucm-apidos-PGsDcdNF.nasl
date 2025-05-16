#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182614);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/18");

  script_cve_id("CVE-2023-20259");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf44755");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-apidos-PGsDcdNF");
  script_xref(name:"IAVA", value:"2023-A-0527");

  script_name(english:"Cisco Unified Communications Manager DoS (cisco-sa-cucm-apidos-PGsDcdNF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager running on the remote host is affected by
a denial of service (DoS) vulnerability. Due to improper API authentication and incomplete verification of the API
request, an unauthenticated, remote attacker can send a specially crafted HTTP request to a specific API causing a
DoS condition due to high CPU utilization. A successful attack can negatively impact user traffic and management
.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-apidos-PGsDcdNF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19b66d72");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf44755");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs  CSCwf44755");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/04");
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

var version_active = get_kb_item('Host/Cisco/show_version_active');
if ('CSCwf44755' >< version_active)
  audit(AUDIT_HOST_NOT, 'affected due to presence of hotfix');

var fix;
if (product_info['version'] =~ "^14\.")
  fix = 'Patch ciscocm.V14SU3_CSCwf44755.cop';
else
  fix = '12.5(1)SU8';

var vuln_ranges = [
    # 12.5(1)SU7 - https://software.cisco.com/download/home/286322286/type/286319236/release/12.5(1)SU7
    # 12.5(1)SU8 - https://software.cisco.com/download/home/286322286/type/286319236/release/12.5(1)SU8
    {'min_ver': '12.5.1.17900.64', 'fix_ver': '12.5.1.18900.40'},
    # 14SU3 - https://software.cisco.com/download/home/286328117/type/286319236/release/14SU3
    # Treating a most minor version bump as fixed version due to the only fix being a hotpatch
    {'min_ver': '14.0.1.13900.155', 'fix_ver': '14.0.1.13900.156'}
];


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['display_version'],
  'fix'      , fix,
  'bug_id'   , 'CSCwf44755',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);

