#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234569);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2024-51988");

  script_name(english:"RabbitMQ 3.12.x < 3.12.11 Queue Deletion Authorization Bypass");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RabbitMQ installed on the remote host is 3.12.x prior to 3.2.11. It is, therefore, affected by an
authorization bypass vulnerability:

  - RabbitMQ is a feature rich, multi-protocol messaging and streaming broker. In affected versions queue deletion via
    the HTTP API was not verifying the `configure` permission of the user. Users who had all of the following: 1.
    Valid credentials, 2. Some permissions for the target virtual host & 3. HTTP API access. could delete queues it had
    no (deletion) permissions for. (CVE-2024-51988)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
# https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-pj33-75x5-32j4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef3eadf7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RabbitMQ version 3.12.11 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-51988");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
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

# Not checking if management plugin is enabled
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'RabbitMQ', app_info.version);

var constraints = [{'min_version':'3.12', 'fixed_version' : '3.12.11'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
