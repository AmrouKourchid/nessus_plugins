#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130276);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2019-11043");
  script_xref(name:"IAVA", value:"2019-A-0399-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"PHP < 7.1.33 / 7.2.x < 7.2.24 / 7.3.x < 7.3.11 Remote Code Execution Vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web server is 
prior to 7.1.33, 7.2.x prior to 7.2.24, or 7.3.x prior to 7.3.11. It is, 
therefore, affected by a remote code execution vulnerability due to insufficient 
validation of user input. An unauthenticated, remote attacker can exploit this, by sending a specially crafted request,
to cause the execution of arbitrary code by breaking the fastcgi_split_path_info directive.");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.11");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.2.24");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.1.33");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=78599");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('audit.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');

if ((report_paranoia < 2) && backported) audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [
    {'min_version':'5.6.0alpha1', 'fixed_version':'7.1.33'},
    {'min_version':'7.2.0alpha1', 'fixed_version':'7.2.24'},
    {'min_version':'7.3.0alpha1', 'fixed_version':'7.3.11'}
    ];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
