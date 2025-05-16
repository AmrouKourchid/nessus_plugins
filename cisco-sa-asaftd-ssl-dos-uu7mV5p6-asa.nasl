#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200305);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/12");

  script_cve_id("CVE-2023-20006");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc94466");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf62729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ssl-dos-uu7mV5p6");

  script_name(english:"Cisco Adaptive Security Appliance Software SSL/TLS DoS (cisco-sa-asaftd-ssl-dos-uu7mV5p6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the hardware-based SSL/TLS cryptography functionality of Cisco Adaptive Security Appliance (ASA)
Software and Cisco Firepower Threat Defense (FTD) Software for Cisco Firepower 2100 Series Appliances could allow an 
unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service 
(DoS) condition. This vulnerability is due to an implementation error within the cryptographic functions for SSL/TLS 
traffic processing when they are offloaded to the hardware. An attacker could exploit this vulnerability by sending 
a crafted stream of SSL/TLS traffic to an affected device. A successful exploit could allow the attacker to cause an
unexpected error in the hardware-based cryptography engine, which could cause the device to reload.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ssl-dos-uu7mV5p6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e1ec90c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc94466");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf62729");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwc94466 and CSCwf62729");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');
var model = product_info['model'];

if (model !~ "(FPR-?|Firepower)\s*(21[0-9]{2}|2K)")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_versions = make_list(
  '9.16.4',
  '9.16.4.9',
  '9.16.4.14',
  '9.16.4.18',
  '9.16.4.19',
  '9.16.4.27',
  '9.17.1.30',
  '9.17.1.33',
  '9.18.2',
  '9.18.2.5',
  '9.18.2.7',
  '9.18.2.8',
  '9.18.3',
  '9.18.3.39',
  '9.18.3.46',
  '9.18.3.53',
  '9.19.1',
  '9.19.1.5',
  '9.19.1.9',
  '9.19.1.12',
  '9.19.1.18'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['asa_ssl_tls']];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwc94466, CSCwf62729'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
;