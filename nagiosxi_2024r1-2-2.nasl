#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216939);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id(
    "CVE-2024-54958", 
    "CVE-2024-54959", 
    "CVE-2024-54960", 
    "CVE-2024-54961");
    script_xref(name:"IAVB", value:"2024-B-0031");

  script_name(english:"Nagios XI < 2024R1.2.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version of Nagios XI, the remote host is affected by multiple vulnerabilities, including
the following:

  - Nagios XI 2024R1.2.2 is vulnerable to a Cross-Site Request Forgery (CSRF) attack through the Favorites component, 
    enabling POST-based Cross-Site Scripting (XSS). An attacker can exploit this by tricking authenticated users into 
    executing malicious actions, such as injecting scripts, which may compromise user sessions or lead to unauthorized 
    actions within the application. (CVE-2024-549)

  - Nagios XI 2024R1.2.2 is affected by a SQL Injection vulnerability in the History Tab component. A remote attacker 
    can exploit this flaw by submitting a crafted payload, allowing unauthorized access to the underlying database. 
    This could result in data exposure, modification, or complete compromise of the application. (CVE-2024-54960)

  - Nagios XI 2024R1.2.2 exposes a vulnerability that allows unauthenticated users to access multiple pages displaying 
    the usernames and email addresses of all current users. This information disclosure flaw can aid attackers in 
    reconnaissance activities, potentially leading to phishing attacks or further exploitation. (CVE-2024-54961)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/products/security/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nagios XI 2024R1.2.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54958");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-54958");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nagios_enterprise_detect.nasl", "nagiosxi_nix_installed.nbin");
  script_require_ports("installed_sw/nagios_xi", "installed_sw/Nagios XI");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::nagiosxi::get_app_info();

var constraints = [
    {'fixed_version': '2024R1.2.3'}
];

vcf::nagiosxi::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, default_fix:'2024R1.2.3', flags:{sqli:TRUE});
