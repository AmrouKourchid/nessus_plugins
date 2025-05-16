#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181758);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2023-40931",
    "CVE-2023-40932",
    "CVE-2023-40933",
    "CVE-2023-40934"
  );
  script_xref(name:"IAVB", value:"2023-B-0071-S");

  script_name(english:"Nagios XI < 5.11.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version of Nagios XI, the remote host is affected by multiple vulnerabilities, including
the following:

  - A SQL injection vulnerability in Nagios XI from version 5.11.0 up to and including 5.11.1 allows authenticated attackers 
    to execute arbitrary SQL commands via the ID parameter in the POST request to /nagiosxi/admin/banner_message-ajaxhelper.php 
    (CVE-2023-40931)

  - A Cross-site scripting (XSS) vulnerability in Nagios XI version 5.11.1 and below allows authenticated attackers with access 
    to the custom logo component to inject arbitrary javascript or HTML via the alt-text field. This affects all pages containing 
    the navbar including the login page which means the attacker is able to to steal plaintext credentials. 
    (CVE-2023-40932)

  - A SQL injection vulnerability in Nagios XI v5.11.1 and below allows authenticated attackers with announcement banner 
    configuration privileges to execute arbitrary SQL commands via the ID parameter sent to the update_banner_message() function. 
    (CVE-2023-40933)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/products/security/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nagios XI 5.11.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40933");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nagios_enterprise_detect.nasl", "nagiosxi_nix_installed.nbin");
  script_require_ports("installed_sw/nagios_xi", "installed_sw/Nagios XI");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::nagiosxi::get_app_info();

var constraints = [
    {'fixed_version': '5.11.2'}
];

vcf::nagiosxi::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE, sqli:TRUE}, default_fix:'5.11.2');
