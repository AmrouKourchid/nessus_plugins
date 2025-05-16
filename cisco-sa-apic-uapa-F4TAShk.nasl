#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180453);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2023-20230");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe56828");
  script_xref(name:"CISCO-SA", value:"cisco-sa-apic-uapa-F4TAShk");
  script_xref(name:"IAVA", value:"2023-A-0441-S");

  script_name(english:"Cisco APIC Unauthorized Policy Actions (cisco-sa-apic-uapa-F4TAShk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the restricted security domain implementation of Cisco Application Policy Infrastructure Controller 
(APIC) could allow an authenticated, remote attacker to read, modify, or delete non-tenant policies (for example, 
access policies) created by users associated with a different security domain on an affected system. This vulnerability 
is due to improper access control when restricted security domains are used to implement multi-tenancy for policies 
outside the tenant boundaries. An attacker with a valid user account associated with a restricted security domain could 
exploit this vulnerability. A successful exploit could allow the attacker to read, modify, or delete policies created 
by users associated with a different security domain. Exploitation is not possible for policies under tenants that an
attacker has no authorization to access.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-uapa-F4TAShk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9beddf20");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe56828");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe56828");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('http.inc');

# Can't Determine Restricted Security Domain Configuration
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:443); 
var product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

var vuln_ranges = [
  {'min_ver': '5.2', 'fix_ver': '5.2(8d)'},
  {'min_ver': '6.0', 'fix_ver': '6.0(3d)'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe56828',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
