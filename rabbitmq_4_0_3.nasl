#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235082);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2025-30219");
  script_xref(name:"IAVA", value:"2025-A-0311");

  script_name(english:"RabbitMQ < 3.13.8 / 4.0.x < 4.0.3 XSS (GHSA-g58g-82mw-9m3p)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"RabbitMQ is a messaging and streaming broker. Versions prior to 4.0.3 are vulnerable to a sophisticated attack that
could modify virtual host name on disk and then make it unrecoverable (with other on disk file modifications) can
lead to arbitrary JavaScript code execution in the browsers of management UI users. When a virtual host on a RabbitMQ
node fails to start, recent versions will display an error message (a notification) in the management UI. The error
message includes virtual host name, which was not escaped prior to open source RabbitMQ 4.0.3 and Tanzu RabbitMQ 4.0.3,
3.13.8. An attack that both makes a virtual host fail to start and creates a new virtual host name with an XSS code
snippet or changes the name of an existing virtual host on disk could trigger arbitrary JavaScript code execution in
the management UI (the user's browser). Open source RabbitMQ `4.0.3` and Tanzu RabbitMQ `4.0.3` and `3.13.8` patch the
issue.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
# https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-pj33-75x5-32j4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef3eadf7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RabbitMQ version 3.12.11 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30219");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:rabbitmq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

# Not checking if management plugin is enabled
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'RabbitMQ', app_info.version);

var constraints = [
  {'min_version':'0.0', 'fixed_version' : '3.13.8'},
  {'min_version':'4.0.0', 'fixed_version' : '4.0.3'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
