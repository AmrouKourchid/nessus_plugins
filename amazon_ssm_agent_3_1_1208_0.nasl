#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191491);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2022-29527");

  script_name(english:"Amazon SSM Agent < 3.1.1208.0");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon SSM Agent installed on the remote host is prior to 3.1.1208.0. It is, therefore, affected by a
vulnerability as referenced in the advisory.

  - Amazon AWS amazon-ssm-agent before 3.1.1208.0 creates a world-writable sudoers file, which allows local
    attackers to inject Sudo rules and escalate privileges to root. This occurs in certain situations
    involving a race condition. (CVE-2022-29527)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/aws/amazon-ssm-agent/releases/tag/3.1.1208.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05f4b3a2");
  script_set_attribute(attribute:"solution", value:
"Upgrade Amazon SSM Agent to version 3.1.1208.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:amazon:ssm_agent");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("amazon_ssm_agent_linux_installed.nbin", "amazon_ssm_agent_macos_installed.nbin", "amazon_ssm_agent_win_installed.nbin");
  script_require_keys("installed_sw/Amazon SSM Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Amazon SSM Agent');

var constraints = [
  { 'fixed_version' : '3.1.1208.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
