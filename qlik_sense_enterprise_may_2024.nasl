#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198142);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-36077");
  script_xref(name:"IAVA", value:"2024-A-0313");

  script_name(english:"Qlik Sense Enterprise Privilage Escalation (CVE-2024-36077)");

  script_set_attribute(attribute:"synopsis", value:
"A data analytics server installed on the remote Windows host is affected by a privilage escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Qlik Sense Enterprise installed on the remote Windows host is prior to May 2022 prior to Patch 18,
August 2022 prior to Patch 17, November 2022 prior to Patch 14, February 2023 prior to Patch 14, May 2023 prior 
to Patch 16, August 2023 prior to Patch 14, November 2023 prior to patch 9, or February 2024 prior to patch 4. It is, 
therefore, affected by a privilage escalation vulnerability. Due to improper input validation, a remote attacker with 
existing privileges is able to elevate those privilages to the internal system role, which in turns allows them to 
execute commands on the server. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.qlik.com/t5/Official-Support-Articles/High-Severity-Security-fixes-for-Qlik-Sense-Enterprise-for/ta-p/2452509
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?906c7de4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Qlik Sense Enterprise in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36077");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qlik:qlik_sense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qlik_sense_enterprise_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Qlik Sense Enterprise");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Qlik Sense Enterprise', win_local:TRUE);

var constraints = [
  # Version information taken from https://github.com/qlik-download/qlik-sense-server/releases
  { 'min_version': '14.67.7', 'fixed_version' : '14.67.34', 'fixed_display': 'May 2022 Patch 18 (14.67.34)' },
  { 'min_version': '14.78.5', 'fixed_version' : '14.78.25', 'fixed_display': 'August 2022 Patch 17 (14.78.25)' },
  { 'min_version': '14.97.3', 'fixed_version' : '14.97.19', 'fixed_display': 'November 2022 Patch 14 (14.97.19)' },
  { 'min_version': '14.113.2', 'fixed_version' : '14.113.19', 'fixed_display': 'February 2023 Patch 14 (14.113.19)' },
  { 'min_version': '14.129.6', 'fixed_version' : '14.129.23', 'fixed_display': 'May 2023 Patch 16 (14.129.23)' },
  { 'min_version': '14.139.4', 'fixed_version' : '14.139.21', 'fixed_display': 'August 2023 Patch 14 (14.139.21)' },
  { 'min_version': '14.159.4', 'fixed_version' : '14.159.14', 'fixed_display': 'November 2023 Patch 9 (14.97.17)' },
  { 'min_version': '14.173.3', 'fixed_version' : '14.173.8', 'fixed_display': 'February 2024 Patch 4 (14.173.8)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
