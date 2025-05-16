#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234566);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2023-46118");

  script_name(english:"RabbitMQ 3.11.x < 3.11.24 / 3.12.x < 3.12.7 Denial of Service");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RabbitMQ installed on the remote host is 3.11.x prior to 3.11.24, or 3.12.x prior to 3.12.7. It is,
therefore, affected by a denial of service vulnerability:

  - RabbitMQ is a multi-protocol messaging and streaming broker. HTTP API did not enforce an HTTP request body limit,
    making it vulnerable for denial of service (DoS) attacks with very large messages. An authenticated user with
    sufficient credentials can publish a very large messages over the HTTP API and cause target node to be terminated
    by an 'out-of-memory killer'-like mechanism. (CVE-2023-46118)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
# https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-w6cq-9cf4-gqpg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3dbcbd23");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RabbitMQ version 3.11.24 or 3.12.7 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46118");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/23");
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

var constraints = [
  {'min_version':'3.11', 'fixed_version' : '3.11.24'},
  {'min_version':'3.12', 'fixed_version' : '3.12.7'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING 
);
