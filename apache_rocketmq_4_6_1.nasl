#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185453);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/13");

  script_cve_id("CVE-2019-17572");

  script_name(english:"Apache RocketMQ 4.2.0 < 4.6.1 Directory Traversal (CVE-2023-37582)");

  script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote web server is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"In Apache RocketMQ 4.2.0 to 4.6.0, when the automatic topic creation in the broker is turned on by default, 
an evil topic like ../../../../topic2020 is sent from rocketmq-client to the broker, a topic folder will be 
created in the parent directory in brokers, which leads to a directory traversal vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://devhub.checkmarx.com/cve-details/cve-2019-17572");
  script_set_attribute(attribute:"see_also", value:"https://rocketmq.apache.org/release-notes/2020/2/14/4.6.1");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2020/q2/112");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache RocketMQ version 4.6.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17572");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:rocketmq");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_rocketmq_detect.nbin");
  script_require_keys("installed_sw/Apache RocketMQ");

  exit(0);
}

include('vcf.inc');

var app = 'Apache RocketMQ';
var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { 'min_version' : '4.2.0', 'max_version' : '4.6.0', 'fixed_version' : '4.6.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
