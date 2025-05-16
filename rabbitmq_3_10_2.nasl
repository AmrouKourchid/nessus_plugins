#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234567);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2022-31008");

  script_name(english:"RabbitMQ 3.8.x < 3.8.32 / 3.9.x < 3.9.18 / 3.10.x < 3.10.2 Predictable credential obfuscation");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RabbitMQ installed on the remote host is 3.8.x prior to 3.8.32, 3.9.x prior to 3.9.18, or 3.10.x prior
to 3.10.2. It is, therefore, affected by a vulnerability:

  - RabbitMQ is a multi-protocol messaging and streaming broker. In affected versions the shovel and federation plugins
    perform URI obfuscation in their worker (link) state. The encryption key used to encrypt the URI was seeded with a
    predictable secret. This means that in case of certain exceptions related to Shovel and Federation plugins,
    reasonably easily deobfuscatable data could appear in the node log. (CVE-2022-31008)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
# https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-v9gv-xp36-jgj8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be4b6264");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RabbitMQ version 3.8.32, 3.9.18, or 3.10.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31008");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
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

# Not checking if Shovel and Federation plugins are enabled
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'RabbitMQ', app_info.version);

var constraints = [
  {'min_version':'3.8',  'fixed_version' : '3.8.32'},
  {'min_version':'3.9',  'fixed_version' : '3.9.18'},
  {'min_version':'3.10', 'fixed_version' : '3.10.2'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE 
);
