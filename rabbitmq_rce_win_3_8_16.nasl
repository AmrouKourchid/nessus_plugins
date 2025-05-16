#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198217);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2021-22117");
  script_xref(name:"IAVB", value:"2021-B-0029-S");

  script_name(english:"Pivotal RabbitMQ 3.8.x < 3.8.16 Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote web server is affected by arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"RabbitMQ installers on Windows prior to version 3.8.16 do not harden plugin directory permissions, potentially 
allowing attackers with sufficient local filesystem permissions to add arbitrary plugins.

A malicious actor can execute arbitrary code on the running RabbitMQ server by adding arbitrary plugins. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://tanzu.vmware.com/security/cve-2021-22117");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rabbitmq/rabbitmq-server/releases/tag/v3.8.15");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rabbitmq/rabbitmq-server/releases/tag/v3.8.16");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pivotal RabbitMQ version 3.8.16 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22117");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:rabbitmq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_rabbitmq_win_installed.nbin");
  script_require_keys("installed_sw/RabbitMQ");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'RabbitMQ');

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  {'min_version' : '3.8.0',  'fixed_version' : '3.8.16'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);