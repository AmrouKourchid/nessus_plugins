#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178019);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id("CVE-2023-20028", "CVE-2023-20119", "CVE-2023-20120");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd50087");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd50094");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe12624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe14247");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe18586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-wsa-xss-cP9DuEmq");
  script_xref(name:"IAVA", value:"2023-A-0495");

  script_name(english:"Cisco Secure Email and Web Manager XSS (cisco-sa-esa-sma-wsa-xss-cP9DuEmq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager is affected by cross-site scripting 
vulnerabilities. The vulnerability is due to insufficient validation of user input. An attacker could exploit this 
by persuading a user of an affected interface to click a crafted link. A successful exploit could allow the attacker to 
execute arbitrary script code in the context of the affected interface or access sensitive, browser-based information.
  
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-wsa-xss-cP9DuEmq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f43c9b2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd50087");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd50094");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe12624");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe14247");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe18586");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd50087, CSCwd50094, CSCwe12624, CSCwe14247,
CSCwe18586");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '15.0.0.0'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd50087, CSCwd50094, CSCwe12624, CSCwe14247, CSCwe18586',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);