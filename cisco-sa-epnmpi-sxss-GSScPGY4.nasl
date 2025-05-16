#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233865);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-20120", "CVE-2025-20203");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm66634");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm51867");
  script_xref(name:"CISCO-SA", value:"cisco-sa-epnmpi-sxss-GSScPGY4");
  script_xref(name:"IAVA", value:"2025-A-0217");

  script_name(english:"Cisco Prime Infrastructure Multiple Vulnerabilities (cisco-sa-epnmpi-sxss-GSScPGY4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Prime Infrastructure installed on the remote host is prior to 3.10.6.1. It is, therefore, affected
by multiple vulnerabilities:

  - A vulnerability in the web-based management interface of Cisco Evolved Programmable Network Manager
    (EPNM) and Cisco Prime Infrastructure could allow an authenticated, remote attacker to conduct a stored
    cross-site scripting (XSS) attack against users of the interface of an affected system. The vulnerability
    exists because the web-based management interface does not properly validate user-supplied input. An
    attacker could exploit this vulnerability by inserting malicious code into specific data fields in the
    interface. A successful exploit could allow the attacker to execute arbitrary script code in the context
    of the affected interface or access sensitive, browser-based information. To exploit this vulnerability,
    the attacker must have valid administrative credentials.

  - A vulnerability in the web-based management interface of Cisco Evolved Programmable Network Manager
    (EPNM) and Cisco Prime Infrastructure could allow an unauthenticated, remote attacker to conduct a stored
    cross-site scripting (XSS) attack against a user of the interface on an affected device. This vulnerability
    is due to insufficient validation of user-supplied input by the web-based management interface of an
    affected system. An attacker could exploit this vulnerability by injecting malicious code into specific
    pages of the interface. A successful exploit could allow the attacker to execute arbitrary script code
    in the context of the affected interface or access sensitive, browser-based information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-epnmpi-sxss-GSScPGY4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7006e37d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm66634");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm51867");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20120");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Prime Infrastructure');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  {'fixed_version': '3.10.6.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
