#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187163);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2023-48084", "CVE-2023-48085");

  script_name(english:"Nagios XI < 5.11.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version of Nagios XI, the remote host is affected by multiple vulnerabilities, including
the following:

  - A SQL injection vulnerability in the bulk modification tool allowing an unauthenticated remote attacker to
    run arbitrary code in the context of the database server. (CVE-2023-48084)

  - A remote code execution vulnerability in the command_test.php component. (CVE-2023-48085)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/products/security/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nagios XI 5.11.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48085");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
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

include('http_func.inc');
include('vcf_extras.inc');

var app_info = vcf::nagiosxi::get_app_info();

var constraints = [
    {'fixed_version': '5.11.3'}
];

vcf::nagiosxi::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{sqli:TRUE}, default_fix:'5.11.3');
