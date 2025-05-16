#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188002);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2023-20257", "CVE-2023-20260", "CVE-2023-20271");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf81862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf81865");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf81870");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf83557");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf83560");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf83565");
  script_xref(name:"CISCO-SA", value:"cisco-sa-pi-epnm-wkZJeyeq");
  script_xref(name:"IAVA", value:"2024-A-0022-S");

  script_name(english:"Cisco Evolved Programmable Network Multiple Vulnerabilities (cisco-sa-pi-epnm-wkZJeyeq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Prime Infrastructure installed on the remote host is prior to 3.10.4. It is, therefore, affected
by multiple vulnerabilities:

  - A vulnerability in the web-based management interface of Cisco EPNM and Cisco Prime 
  Infrastructure could allow an authenticated, remote attacker to conduct SQL injection 
  attacks on an affected system. This vulnerability is due to improper validation of 
  user-submitted parameters. (CVE-2023-20271)

  - A vulnerability in the application CLI of Cisco EPNM and Cisco Prime Infrastructure 
  could allow an authenticated, local attacker to gain elevated privileges. This 
  vulnerability is due to improper processing of command line arguments to application 
  scripts. (CVE-2023-20260)

  -A vulnerability in the web-based management interface of Cisco EPNM and Cisco Prime 
  Infrastructure could allow an authenticated, remote attacker to conduct XSS attacks. 
  This vulnerability is due to improper validation of user-supplied input to the 
  web-based management interface. (CVE-2023-20257)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pi-epnm-wkZJeyeq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53497b93");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf15468");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf81862");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf81865");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf81870");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf83557");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf83560");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf83565");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20271");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-20260");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:evolved_programmable_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_epn_manager_detect.nbin");
  script_require_keys("installed_sw/Cisco EPN Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco EPN Manager');

var constraints = [
  {'fixed_version': '7.1.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
