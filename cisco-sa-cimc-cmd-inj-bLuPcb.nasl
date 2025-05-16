#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197063);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/16");

  script_cve_id("CVE-2024-20356");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi42996");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi43001");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi43005");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj41082");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cimc-cmd-inj-bLuPcb");
  script_xref(name:"IAVA", value:"2024-A-0250");

  script_name(english:"Cisco Integrated Management Controller Web-Based Management Interface Command Injection (cisco-sa-cimc-cmd-inj-bLuPcb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Integrated Management Controller Web-Based Management Interface is
affected by a command injection vulnerability. Due to insufficient user input validation, an authenticated, remote 
attacker with Administrator-level privileges could perform command injection attacks on an affected system and elevate 
their privileges to root.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-cmd-inj-bLuPcb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7799f84a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi42996");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi43001");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi43005");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj41082");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwi42996, CSCwi43001, CSCwi43005, CSCwj41082");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20356");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version", "Host/Cisco/CIMC/model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Computing System (Management Software)');

var model = toupper(product_info.model);

if (empty_or_null(model) ||
 (model !~ "ENCS5\d+" && model !~ "C83\d+[\s-]UCPE" && model !~ "E\d+[SD]" && model !~ "C\d+[\s-]?M[567]" && model !~ "S3260")) 
    audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [];

# 5000 Series ENCS
# Catalyst 8300 Series Edge uCPE
if (model =~ "ENCS5\d+" || model =~ "C83\d+[\s-]UCPE")
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.14.1'}
  ];

# C-Series M5, M6, M7
if (model =~ "C\d+[\s-]?M[4567]")
{
  if ("M5" >< model)
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '4.1(3n)'},
      {'min_ver': '4.2', 'fix_ver': '4.2(3j)'},
      {'min_ver': '4.3', 'fix_ver': '4.3(2.240009)'}
    ];
  else if ("M6" >< model)
    vuln_ranges = [
      {'min_ver': '4.2', 'fix_ver': '4.2(3j)'},
      {'min_ver': '4.3', 'fix_ver': '4.3(3.240009)'}
    ];
  else if ("M7" >< model)
    vuln_ranges = [
      {'min_ver': '4.3', 'fix_ver': '4.3(3.240022)'}
    ];
}

# E-Series M2, M3, M6
if (model =~ "E\d+[SD]")
{
  if (model =~ "M[23]|E140S|E160D|E180D|E160S|E1120D")
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '3.2.15.3'}
    ];
  else if (model =~ "M6|E1100D")
    vuln_ranges = [
      {'min_ver': '4.12', 'fix_ver': '4.12.2'}
    ];
}

# only available S-Series seems to be UCS S3260
if (model =~ "S3260")
  vuln_ranges = [
    {'min_ver': '4.0', 'fix_ver': '4.1(3n)'},
    {'min_ver': '4.2', 'fix_ver': '4.2(3k)'},
    {'min_ver': '4.3', 'fix_ver': '4.3(2.240009)'}
  ];


var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwi42996, CSCwi43001, CSCwi43005, CSCwj41082',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
