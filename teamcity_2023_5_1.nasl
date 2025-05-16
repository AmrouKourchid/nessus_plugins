#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182201);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/25");

  script_cve_id(
    "CVE-2023-38061",
    "CVE-2023-38062",
    "CVE-2023-38063",
    "CVE-2023-38064",
    "CVE-2023-38065",
    "CVE-2023-38066",
    "CVE-2023-38067"
  );

  script_name(english:"TeamCity Server < 2023.05.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of JetBrains TeamCity running on the
remote host is a version prior to 2023.05.1. It is, therefore, affected by
multiple vulnerabilities:
    
  - In JetBrains TeamCity before 2023.05.1 stored XSS when using a custom theme was possible
    (CVE-2023-38061)

  - In JetBrains TeamCity before 2023.05.1 parameters of the 'password' type could be shown in the UI in certain 
    composite build configurations (CVE-2023-38062)

  - In JetBrains TeamCity before 2023.05.1 stored XSS while running custom builds was possible
    (CVE-2023-38063)

Note that Nessus did not actually test for these issues, but instead
has relied on the version found in the server's banner.");
  # https://www.jetbrains.com/privacy-security/issues-fixed/?product=TeamCity&version=2023.05.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b68fc20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains TeamCity version 2023.05.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38067");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
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
  { 'fixed_version' : '2023.05.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
