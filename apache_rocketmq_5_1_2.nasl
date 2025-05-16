#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185454);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/13");

  script_cve_id("CVE-2023-37582");

  script_name(english:"Apache RocketMQ < 4.9.7 / 5.x < 5.1.2 RCE (CVE-2023-37582)");

  script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote web server is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The RocketMQ NameServer component still has a remote command execution vulnerability as the CVE-2023-33246 issue
was not completely fixed in version 4.9.6 / 5.1.1. When NameServer address are leaked on the extranet and lack 
permission verification, an attacker can exploit this vulnerability by using the update configuration function 
on the NameServer component to execute commands as the system users that RocketMQ is running as.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://www.sangfor.com/farsight-labs-threat-intelligence/cybersecurity/cve-2023-37582-apache-rocketmq-remote-command-execution-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1ed2c96");
  script_set_attribute(attribute:"see_also", value:"https://rocketmq.apache.org/release-notes");
  # https://lists.apache.org/thread/m614czxtpvlztd7mfgcs2xcsg36rdbnc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20984901");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache RocketMQ version 4.9.7, 5.1.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-37582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
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
  { 'fixed_version' : '4.9.7'},
  { 'min_version' : '5.0.0', 'fixed_version' : '5.1.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
