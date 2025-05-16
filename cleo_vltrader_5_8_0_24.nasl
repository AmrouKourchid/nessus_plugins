#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213085);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-55956");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/01/07");
  script_xref(name:"IAVA", value:"2024-A-0825");

  script_name(english:"Cleo VLTrader < 5.8.0.24 Unauthenticated Arbitrary Command Execution (CVE-2024-55956)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an unauthenticated arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cleo VLTrader running on the remote host is prior to 5.8.0.24. It is, therefore, affected by an
unauthenticated arbitrary command execution vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.cleo.com/hc/en-us/articles/28408134019735-Cleo-Product-Security-Update-CVE-2024-55956
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d623686d");
  # https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c45e20b2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cleo VLTrader version 5.8.0.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-55956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cleo LexiCom, VLTrader, and Harmony Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cleo:vltrader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cleo_vltrader_detect.nbin");
  script_require_keys("installed_sw/Cleo VLTrader");
  script_require_ports("Services/www", 8080, 443, "Services/smtp", 25, "Services/ftp", 21, "Services/ssh", 22);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'Cleo VLTrader';
get_install_count(app_name:app, exit_if_zero:TRUE);

var ports = make_list(8080, 443, 25, 21, 22);

var www_ports = get_kb_list("Services/www");
if (!empty_or_null(www_ports)) ports = make_list(ports, www_ports);

var smtp_ports = get_kb_list("Services/smtp");
if (!empty_or_null(smtp_ports)) ports = make_list(ports, smtp_ports);

var ftp_ports = get_kb_list("Services/ftp");
if (!empty_or_null(ftp_ports)) ports = make_list(ports, ftp_ports);

var ssh_ports = get_kb_list("Services/ssh");
if (!empty_or_null(ssh_ports)) ports = make_list(ports, ssh_ports);

ports = list_uniq(ports);

var constraints = [
  { 'fixed_version' : '5.8.0.24' }
];

var port = branch(ports);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);