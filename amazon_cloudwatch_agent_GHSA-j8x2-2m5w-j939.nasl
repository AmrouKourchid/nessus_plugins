#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191143);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/29");

  script_cve_id("CVE-2022-23511");

  script_name(english:"Amazon CloudWatch Agent < 1.247355 (GHSA-j8x2-2m5w-j939)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon CloudWatch Agent installed on the remote host is prior to 1.247355. It is, therefore, affected by
a vulnerability as referenced in the GHSA-j8x2-2m5w-j939 advisory.

  - A privilege escalation issue exists within the Amazon CloudWatch Agent for Windows, software for
    collecting metrics and logs from Amazon EC2 instances and on-premises servers, in versions up to and
    including v1.247354. When users trigger a repair of the Agent, a pop-up window opens with SYSTEM
    permissions. Users with administrative access to affected hosts may use this to create a new command
    prompt as NT AUTHORITY\SYSTEM. To trigger this issue, the third party must be able to access the affected
    host and elevate their privileges such that they're able to trigger the agent repair process. They must
    also be able to install the tools required to trigger the issue. This issue does not affect the CloudWatch
    Agent for macOS or Linux. Agent users should upgrade to version 1.247355 of the CloudWatch Agent to
    address this issue. There is no recommended work around. Affected users must update the installed version
    of the CloudWatch Agent to address this issue. (CVE-2022-23511)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade Amazon CloudWatch Agent based upon the guidance specified in GHSA-j8x2-2m5w-j939.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23511");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:amazon:cloudwatch_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("amazon_cloudwatch_agent_win_installed.nbin");
  script_require_keys("installed_sw/Amazon CloudWatch Agent");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Amazon CloudWatch Agent', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '1.247355' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
