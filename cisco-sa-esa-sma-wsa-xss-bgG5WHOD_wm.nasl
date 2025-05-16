#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197884);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2024-20256", "CVE-2024-20258", "CVE-2024-20383");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe88788");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe91887");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf84882");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf93368");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi59618");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj12619");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-wsa-xss-bgG5WHOD");
  script_xref(name:"IAVA", value:"2024-A-0294-S");

  script_name(english:"Cisco Secure Email and Web Manager Multiple Vulnerabilities (cisco-sa-esa-sma-wsa-xss-bgG5WHOD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager is affected by multiple vulnerabilities.

  - A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Email 
    could allow an authenticated, remote attacker to conduct an XSS attack against a user of the interface. 
    This vulnerability is due to insufficient validation of user input. An attacker could exploit this 
    vulnerability by persuading a user of an affected interface to click a crafted link. A successful exploit 
    could allow the attacker to execute arbitrary script code in the context of the affected interface or 
    access sensitive, browser-based information. (CVE-2024-20256)
    
  - A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Email 
    could allow an unauthenticated, remote attacker to conduct an XSS attack against a user of the interface. 
    This vulnerability is due to insufficient validation of user input. An attacker could exploit this 
    vulnerability by persuading a user of an affected interface to click a crafted link. A successful exploit 
    could allow the attacker to execute arbitrary script code in the context of the affected interface or 
    access sensitive, browser-based information. (CVE-2024-20258)

  - A vulnerability in the Cisco Crosswork NSO CLI and the ConfD CLI could allow an authenticated, 
    low-privileged, local attacker to elevate privileges to root on the underlying operating system. The 
    vulnerability is due to an incorrect privilege assignment when specific CLI commands are used. An 
    attacker could exploit this vulnerability by executing an affected CLI command. A successful exploit 
    could allow the attacker to elevate privileges to root on the underlying operating system.
    (CVE-2024-20383)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-wsa-xss-bgG5WHOD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaf46cc2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe88788");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe91887");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf84882");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf93368");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi59618");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj12619");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe88788, CSCwe91887, CSCwf84882,
CSCwf93368, CSCwi59618, CSCwj12619");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20258");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

if (product_info.version =~ "^([0-9]\.)|(1[0-3]\.)|(15\.0)")
{
  var vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '15.5.1.024'} ];
}
else if (product_info.version =~ "^15\.5")
{
  var vuln_ranges = [ { 'min_ver' : '15.5', 'fix_ver' : '15.5.1.024'} ];
}
else
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe88788, CSCwe91887, CSCwf84882, CSCwf93368, CSCwi59618, CSCwj12619',
  'disable_caveat', TRUE,
  'fix'           , '15.5.1-024'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);