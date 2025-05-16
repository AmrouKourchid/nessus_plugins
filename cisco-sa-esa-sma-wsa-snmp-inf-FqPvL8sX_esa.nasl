#%NASL_MIN_LEVEL 80900
#Trusted
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215112);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");

  script_cve_id("CVE-2025-20207");
  script_xref(name:"IAVA", value:"2025-A-0082");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk56452");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-wsa-snmp-inf-FqPvL8sX");

  script_name(english:"Cisco Secure Email Gateway SNMP Polling Information Disclosure (cisco-sa-esa-sma-wsa-snmp-inf-FqPvL8sX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email Gateway is affected by a vulnerability.
  
    - A vulnerability in SNMP polling for Cisco Secure Email Gateway, Cisco Secure Email and Web Manager, and Cisco 
      Secure Web Appliance could allow an authenticated, remote attacker to obtain confidential information about 
      the underlying operating system.
  
  Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-wsa-snmp-inf-FqPvL8sX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d920caf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk56452");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [ 
  WORKAROUND_CONFIG['snmp-config']
];

var vuln_ranges = [
  {'min_ver':'0','max_ver' : '15.0', 'fix_ver' : '15.0.3.2'}, 
  {'min_ver':'15.5','max_ver' : '15.5', 'fix_ver' : '15.5.2.18'},
  {'min_ver' : '16.0', 'max_ver':'16.0', 'fix_ver' : '16.0.0.50'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwk56452',
  'fix'           , 'See vendor advisory',
  'cmds', make_list('snmpconfig')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params: workaround_params
);
