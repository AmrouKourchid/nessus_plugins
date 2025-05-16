#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182203);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/25");

  script_cve_id(
    "CVE-2023-34218",
    "CVE-2023-34219",
    "CVE-2023-34220",
    "CVE-2023-34221",
    "CVE-2023-34222",
    "CVE-2023-34223",
    "CVE-2023-34224",
    "CVE-2023-34225",
    "CVE-2023-34226",
    "CVE-2023-34227",
    "CVE-2023-34228",
    "CVE-2023-34229"
  );

  script_name(english:"TeamCity Server < 2023.05 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of JetBrains TeamCity running on the
remote host is a version prior to 2023.05. It is, therefore, affected by
multiple vulnerabilities:
    
  - In JetBrains TeamCity before 2023.05 bypass of permission checks allowing to perform admin actions was possible
    (CVE-2023-34218)

  - In JetBrains TeamCity before 2023.05 improper permission checks allowed users without appropriate permissions to 
    edit Build Configuration settings via REST API (CVE-2023-34219)

  - In JetBrains TeamCity before 2023.05 stored XSS in the Commit Status Publisher window was possible
    (CVE-2023-34220)

Note that Nessus did not actually test for these issues, but instead
has relied on the version found in the server's banner.");
  # https://www.jetbrains.com/privacy-security/issues-fixed/?product=TeamCity&version=2023.05
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8a6e8e1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains TeamCity version 2023.05 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:teamcity");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_teamcity_web_detect.nbin");
  script_require_keys("installed_sw/JetBrains TeamCity");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'JetBrains TeamCity', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '2023.05' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
