#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205388);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_cve_id("CVE-2024-23321");

  script_name(english:"Apache RocketMQ < 5.3.0 Information Disclosure (CVE-2024-23321)");

  script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote web server is affected by a exposure of sensitive information to an
unauthorized actor vulnerability.");
  script_set_attribute(attribute:"description", value:
"For RocketMQ versions 5.2.0 and below, under certain conditions, there is a risk of exposure of sensitive Information
to an unauthorized actor even if RocketMQ is enabled with authentication and authorization functions. An attacker,
possessing regular user privileges or listed in the IP whitelist, could potentially acquire the administrator's account and
password through specific interfaces. Such an action would grant them full control over RocketMQ, provided they have
access to the broker IP address list. To mitigate these security threats, it is strongly advised that users upgrade to
version 5.3.0 or newer. Additionally, we recommend users to use RocketMQ ACL 2.0 instead of the original RocketMQ ACL when
upgrading to version Apache RocketMQ 5.3.0.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://lists.apache.org/thread/lr8npobww786nrnddd1pcy974r17c830
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa61468c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache RocketMQ version 5.3.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:rocketmq");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_rocketmq_detect.nbin");
  script_require_keys("installed_sw/Apache RocketMQ");

  exit(0);
}

include('vcf.inc');

var app = 'Apache RocketMQ';
var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { 'fixed_version' : '5.3.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
