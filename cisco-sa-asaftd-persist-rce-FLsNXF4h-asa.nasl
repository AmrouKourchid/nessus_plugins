#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193896);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-20359");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi98284");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-persist-rce-FLsNXF4h");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/05/01");
  script_xref(name:"CEA-ID", value:"CEA-2024-0007");
  script_xref(name:"IAVA", value:"2024-A-0252-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Privilege Escalation (cisco-sa-asaftd-persist-rce-FLsNXF4h)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in a legacy capability that allowed for the preloading of VPN clients and plug-ins and that has been
available in Cisco Adaptive Security Appliance (ASA) Software could allow an authenticated, local attacker to execute 
arbitrary code with root-level privileges. Administrator-level privileges are required to exploit this vulnerability.

This vulnerability is due to improper validation of a file when it is read from system flash memory. An attacker could 
exploit this vulnerability by copying a crafted file to the disk0: file system of an affected device. A successful 
exploit could allow the attacker to execute arbitrary code on the affected device after the next reload of the device, 
which could alter system behavior. Because the injected code could persist across device reboots, Cisco has raised the 
Security Impact Rating (SIR) of this advisory from Medium to High.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-persist-rce-FLsNXF4h
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de78a8db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi98284");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20359");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.8.1','fix_ver': '9.12.4.67'},
  {'min_ver': '9.13', 'fix_ver': '9.14.4.24'},
  {'min_ver': '9.15', 'fix_ver': '9.16.4.57'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.39'},
  {'min_ver': '9.18', 'fix_ver': '9.18.4.22'},
  {'min_ver': '9.19', 'fix_ver': '9.19.1.28'},
  {'min_ver': '9.20', 'fix_ver': '9.20.2.10'}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwi98284'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
