#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211591);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2024-36358");

  script_name(english:"Trend Micro Deep Security Agent Local Privilege Escalation (KA-0016724)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by a local privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"A link following vulnerability in Trend Micro Deep Security 20.x agents below build 20.0.1-3180 could allow 
a local attacker to escalate privileges on affected installations.

Note that Nessus has not tested for this issue but has instead relied solely on the application's self-reported 
version number.");
  # https://success.trendmicro.com/en-US/solution/KA-0016724
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3ecffd4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the Deep Security Agent version 20.0.1-3180 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36358");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:deep_security");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_deepsecurity_agent_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Deep Security Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Trend Micro Deep Security Agent', win_local:TRUE);

var constraints = [
  { 'min_version':'20.0', 'fixed_version' : '20.0.1.3180', 'fixed_display' : '20.0.1-3180' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
