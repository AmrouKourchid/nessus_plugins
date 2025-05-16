#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182681);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2023-20235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67351");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rdocker-uATbukKn");
  script_xref(name:"IAVA", value:"2023-A-0528-S");

  script_name(english:"Cisco IOx Application Hosting Environment Privilege Escalation (cisco-sa-rdocker-uATbukKn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability in the on-device
application development workflow feature for the Cisco IOx application hosting infrastructure that could allow an
authenticated, remote attacker to access the underlying operating system as the root user. This vulnerability exists
because Docker containers with the privileged runtime option are not blocked when they are in application development
mode. An attacker could exploit this vulnerability by using the Docker CLI to access an affected device. The application
development workflow is meant to be used only on development systems and not in production systems.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rdocker-uATbukKn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef64204b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67351");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf67351");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
# We cannot test for application development workflow enabled
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco IOS XE Software', product_info.version);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '17.3.8'},
  {'min_ver': '17.4', 'fix_ver': '17.6.6'},
  {'min_ver': '17.7', 'fix_ver': '17.9.5'},
  {'min_ver': '17.10', 'fix_ver': '17.13.1'}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf67351',
  'fix'     , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
