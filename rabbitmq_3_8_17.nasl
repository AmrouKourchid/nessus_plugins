#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234568);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2021-32718");

  script_name(english:"RabbitMQ 3.8.x < 3.8.17 XSS");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RabbitMQ installed on the remote host is 3.8.x prior to 3.8.17. It is, therefore, affected by a
cross-site scripting vulnerability:

  - In rabbitmq-server prior to version 3.8.17, a new user being added via management UI could lead to the user's bane
    being rendered in a confirmation message without proper `<script>` tag sanitization, potentially allowing for
    JavaScript code execution in the context of the page. (CVE-2021-32718)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
# https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-c3hj-rg5h-2772
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5f693b4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RabbitMQ version 3.8.17 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32718");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:rabbitmq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rabbitmq_server_nix_installed.nbin");
  script_require_keys("installed_sw/RabbitMQ");

  exit(0);
}
include('vcf.inc');

var app_info = vcf::get_app_info(app:'RabbitMQ');

if (app_info['Managed'])
  audit(AUDIT_HOST_NOT, 'relevant to this plugin as RabbitMQ was installed by a package manager');

# Not checking if rabbitmq_management plugin is enabled.
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'RabbitMQ', app_info.version);

var constraints = [{'min_version':'3.8', 'fixed_version' : '3.8.17'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_NOTE, 
  flags:{'xss':TRUE}
);
