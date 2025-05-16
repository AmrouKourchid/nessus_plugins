#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210593);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id("CVE-2024-20514");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk83676");
  script_xref(name:"CISCO-SA", value:"cisco-sa-epnmpi-sxss-yyf2zkXs");
  script_xref(name:"IAVA", value:"2024-A-0709-S");

  script_name(english:"Cisco Prime Infrastructure XSS (cisco-sa-epnmpi-sxss-yyf2zkXs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Prime Infrastructure installed on the remote host is 3.10.x prior to 3.10.6. It is, therefore, 
affected by multiple vulnerabilities:

  - A vulnerability in the web-based management interface of Cisco Prime Infrastructure could allow an authenticated, 
    low-privileged, remote attacker to conduct a stored cross-site scripting (XSS) attack against a user of the 
    interface. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-epnmpi-sxss-yyf2zkXs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c5a424a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk83676");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20514");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Prime Infrastructure');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  {'min_version':'3.10', 'fixed_version': '3.10.6'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, flags:{'xss':TRUE}, severity:SECURITY_WARNING);
