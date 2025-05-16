#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234502);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_cve_id("CVE-2023-20267");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe69833");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftdsnort3sip-bypass-LMz2ThKn");


  script_name(english:"Cisco Firepower Threat Defense Software Snort 3 Geolocation IP Filter Bypass (cisco-sa-ftdsnort3sip-bypass-LMz2ThKn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) Software is affected by a vulnerability.

  - A vulnerability in the IP geolocation rules of Snort 3 could allow an unauthenticated, remote attacker to 
    potentially bypass IP address restrictions. This vulnerability exists because the configuration for IP 
    geolocation rules is not parsed properly. An attacker could exploit this vulnerability by spoofing an IP 
    address until they bypass the restriction. A successful exploit could allow the attacker to bypass 
    location-based IP address restrictions. (CVE-2023-20267)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftdsnort3sip-bypass-LMz2ThKn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89c08cab");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe69833");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20267");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [ 
  { 'min_ver' : '7.0.0', 'max_ver' : '7.0.5',   'fix_ver' : '7.0.6' },
  { 'min_ver' : '7.1.0', 'max_ver' : '7.2.3',   'fix_ver' : '7.2.4' },
  { 'min_ver' : '7.3.0', 'max_ver' : '7.3.1.2', 'fix_ver' : '7.4.0' }
];
             
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_snort3_status'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe69833',
  'cmd'     , 'show snort3 status'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
