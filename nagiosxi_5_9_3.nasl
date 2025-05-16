#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181759);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2023-24034", "CVE-2023-24035", "CVE-2023-24036");
  script_xref(name:"IAVB", value:"2023-B-0071-S");

  script_name(english:"Nagios XI < 5.9.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version of Nagios XI, the remote host is affected by multiple vulnerabilities, including
the following:

  - The session ID for API Authentication is generated using uniqid, which is based on the current time. An attacker can 
    brute-force a valid session ID by guessing when a previous user authenticated against the API. (CVE-2023-24036)

  - The “Insecure Backend Ticket” Authentication (which is disabled by default) uses an insecure timing comparison. An 
    attacker can brute-force the admin passive by measuring timing difference in the comparison. (CVE-2023-24035)

  - An issue was discovered in twilio_ajax_handler.php in Nagios XI 5.9.2. An attacker can force a user to visit a 
    malicious site by using an open redirect vulnerability. (CVE-2023-24034)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/products/security/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nagios XI 5.9.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24036");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nagios_enterprise_detect.nasl", "nagiosxi_nix_installed.nbin");
  script_require_ports("installed_sw/nagios_xi", "installed_sw/Nagios XI");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::nagiosxi::get_app_info();

var constraints = [
    {'fixed_version': '5.9.3'}
];

vcf::nagiosxi::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, default_fix:'5.9.3');
