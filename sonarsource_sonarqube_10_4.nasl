#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214332);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-38460");

  script_name(english:"SonarSource SonarQube Server < 9.9.4 / 10.x < 10.4 Information Disclosure (CVE-2024-38460)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SonarSource SonarQube Server running on the remote host is prior to 9.9.4 or 10.x prior to 10.4. It is,
therefore, affected by an information disclosure vulnerability:

  - In SonarQube before 10.4 and 9.9.4 LTA, encrypted values generated using the Settings Encryption feature are
    potentially exposed in cleartext as part of the URL parameters in the logs (such as SonarQube Access Logs, Proxy
    Logs, etc). (CVE-2024-38460)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.sonarsource.com/t/sonarqube-ce-10-3-0-leaking-encrypted-values-in-web-server-logs/108187
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf4c6b9f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SonarSource SonarQube Server version 9.9.4 or 10.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38460");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonarsource:sonarqube");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonarsource_sonarqube_server_web_detect.nbin");
  script_require_keys("installed_sw/SonarSource SonarQube Server");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'SonarSource SonarQube Server';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version':'9.9.4.87374' },
  { 'min_version':'10.0', 'fixed_version':'10.4.0.87286' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);