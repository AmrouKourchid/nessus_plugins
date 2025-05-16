#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210953);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2023-33246");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/09/27");

  script_name(english:"Apache RocketMQ < 4.9.6 / 5.0.x < 5.1.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Apache RocketMQ installed on the remote host is prior to 4.9.6 or 5.1.1. It is, therefore, affected by a
remote code execution vulnerability.

  - For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command
    execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the
    extranet and lack permission verification, an attacker can exploit this vulnerability by using the update
    configuration function to execute commands as the system users that RocketMQ is running as. Additionally,
    an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these
    attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or
    above for using RocketMQ 4.x . (CVE-2023-33246)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/1s8j2c8kogthtpv3060yddk03zq0pxyp");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache RocketMQ version 4.9.6 / 5.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache RocketMQ update config RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:rocketmq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_rocketmq_detect.nbin");
  script_require_keys("installed_sw/Apache RocketMQ");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Apache RocketMQ');

var constraints = [
  { 'fixed_version' : '4.9.6' },
  { 'min_version' : '5.0', 'fixed_version' : '5.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
