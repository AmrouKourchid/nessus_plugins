#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187166);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/15");

  script_cve_id("CVE-2023-50164");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi45131");
  script_xref(name:"CISCO-SA", value:"cisco-sa-struts-C2kCMkmT");

  script_name(english:"Cisco Identity Services Engine RCE (cisco-sa-struts-C2kCMkmT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to
uploading a malicious file which can be used to perform Remote Code Execution.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-struts-C2kCMkmT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5dc0c57b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi45131");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi45131");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50164");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}


include('ccf.inc');
include('cisco_ise_func.inc');

# Paranoid due to the existance of hotfixes
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');
var vuln_ranges = [];

if (empty_or_null(product_info['patches']))
  product_info['patches'] = '0';

if (product_info['version'] =~ "^[0-2]\.")
{
  vuln_ranges =  [{'min_ver':'0.0', 'fix_ver':'2.7.0.356'}];
  required_patch = '10';
  fix_display = '2.7.0.356 Patch 10';
}
else
{
  vuln_ranges =  [{'min_ver':'3.0', 'fix_ver':'3.0.0.458'}];
  required_patch = '7';
  fix_display = '3.0.0.458 Patch 7';
}

var display_ver = product_info['version'];

if (product_info['patches'] != '0')
  display_ver += ' Patch ' + product_info['patches'];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , display_ver,
  'bug_id'        , 'CSCwi45131',
  'disable_caveat', TRUE,
  'fix'           , fix_display
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
