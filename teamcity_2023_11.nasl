#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198068);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id("CVE-2024-35302");
  script_xref(name:"IAVA", value:"2024-A-0296-S");

  script_name(english:"TeamCity Server < 2023.11.0 Restore From Backup XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of JetBrains TeamCity running on the remote host is a 
version prior to 2023.11.0. It is, therefore, affected by Cross Side Scripting Vulnerability during a Restore from Backup.

Note that Nessus did not actually test for these issues, but instead has relied on the version found in the server's banner.");
  # https://www.jetbrains.com/privacy-security/issues-fixed/?product=TeamCity
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48be73f6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains TeamCity version 2023.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35302");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:teamcity");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_teamcity_web_detect.nbin");
  script_require_keys("installed_sw/JetBrains TeamCity");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'JetBrains TeamCity', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '2023.11.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
