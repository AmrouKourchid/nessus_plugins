#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170958);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/20");

  script_cve_id("CVE-2023-20030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd10864");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xxe-inj-GecEHY58");
  script_xref(name:"IAVA", value:"2023-A-0065-S");

  script_name(english:"Cisco Identity Services Engine XXE Injection (cisco-sa-ise-xxe-inj-GecEHY58)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a XML external element (XXE)
vulnerability. A remote attacker, authenticated with Super Admin or Proxy Admin credentials can exploit this
vulnerability by uploading a crafted XML file that contains references to external entities. A successful exploit can
allow the attacker to retrieve files from the local system resulting in a disclosure of confidential information. The
attacker can also cause the web application to perform arbitrary HTTP requests and conduct a server-side request
forgery attack through the affected device or impact the responsiveness of the web-based management interface.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xxe-inj-GecEHY58
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5be7be63");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd10864");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd10864");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '3.0.0.458'},
  {'min_ver': '3.1', 'fix_ver': '3.1.0.518'},
  {'min_ver': '3.2', 'fix_ver': '3.2.0.542'}
];

var required_patch = NULL;

if (product_info['version'] =~ "^3\.1\.")
  required_patch = '6';
else if (product_info['version'] =~ "^3\.2\.")
  required_patch = '1';
else
  required_patch = '7';

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd10864',
  'fix'           , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
