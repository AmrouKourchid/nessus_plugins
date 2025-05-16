#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206393);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/31");

  script_cve_id("CVE-2024-38856");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/17");

  script_name(english:"Apache OFBiz < 18.12.15 Remote Code Execution (CVE-2024-38856)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is potentially affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OFBiz running on the remote host is potentially affected by a remote code execution
vulnerability:

  - Incorrect Authorization vulnerability in Apache OFBiz. This issue affects Apache OFBiz: through 18.12.14. Users are
    recommended to upgrade to version 18.12.15, which fixes the issue. Unauthenticated endpoints could allow execution
    of screen rendering code of screens if some preconditions are met (such as when the screen definitions don't
    explicitly check user's permissions because they rely on the configuration of their endpoints). (CVE-2024-38856)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported model
number");
  # https://lists.apache.org/thread/olxxjk6b13sl3wh9cmp0k2dscvp24l7w
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bda3dae8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OFBiz version 18.12.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38856");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache OFBiz forgotPassword/ProgramExport RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:open_for_business_project");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
var normal_constraints = [{'fixed_version':'18.12.15'}];

var paranoid_constraints = [{'min_version':'18.12', 'max_version':'18.12.14'}];
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
