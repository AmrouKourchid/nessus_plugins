#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214331);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-47910");

  script_name(english:"SonarSource SonarQube Server < 9.9.5 / 10.x < 10.5 GitHub Integration JWT Exfiltration (CVE-2024-47910)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of SonarSource SonarQube Server running on the remote host is prior to 9.9.5 or 10.x prior to 10.5. It is,
therefore, affected by an information disclosure vulnerability:

  - A SonarQube user with the Administrator role can modify an existing configuration of a GitHub integration to
    exfiltrate a pre-signed JWT. (CVE-2024-47910)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.sonarsource.com/t/sonarqube-github-integration-information-leakage/126609
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4900fac0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SonarSource SonarQube Server version 9.9.5 or 10.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47910");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
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
  { 'fixed_version':'9.9.5.90363' },
  { 'min_version':'10.0', 'fixed_version':'10.5.0.89998' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);