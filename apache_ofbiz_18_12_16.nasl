#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207243);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id("CVE-2024-45195", "CVE-2024-45507");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/25");

  script_name(english:"Apache OFBiz < 18.12.16 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OFBiz running on the remote host is prior to 18.12.16. It is, therefore, potentially affected 
by the following vulnerabilities:

  - Server-Side Request Forgery (SSRF), Improper Control of Generation of Code ('Code Injection') vulnerability in 
    Apache OFBiz. (CVE-2024-45507)

  - Direct Request ('Forced Browsing') vulnerability in Apache OFBiz. (CVE-2024-45195) 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported model
number");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/OFBIZ-13132");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/OFBIZ-13130");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OFBiz version 18.12.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45507");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:open_for_business_project");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ofbiz_detect.nasl");
  script_require_keys("installed_sw/Apache Ofbiz", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'Apache Ofbiz';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:8443);
var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var version = vcf::parse_version(app_info.version);
var normal_constraints = [{'fixed_version':'18.12.16'}];

var paranoid_constraints = [{'min_version':'18.12', 'max_version':'18.12.15'}];
var paranoid_check = vcf::check_version(version:version, constraints:paranoid_constraints);

if (!empty_or_null(paranoid_check))
{
  # 18.12.x, audit out unless we are paranoid
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
}

vcf::check_version_and_report(
  app_info:app_info,
  constraints:normal_constraints,
  severity:SECURITY_HOLE
);
