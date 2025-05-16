#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184459);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2022-26503");

  script_name(english:"Veeam Agent for Microsoft Windows 2.x < 4.0.2.2208 / 5.x < 5.0.3.4708 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"Veeam Agent for Microsoft Windows installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Veeam Agent for Microsoft Windows installed on the remote Windows host is affected by a privilege
escalation vulnerability. Deserialization of untrusted data allows local users to run arbitrary code with local system
privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4289");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam Agent for Microsoft Windows version 4.0.2.2208, 5.0.3.4708, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veeam:veeam");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veeam_agent_for_microsoft_windows_installed.nbin");
  script_require_keys("installed_sw/Veeam Agent for Microsoft Windows", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Veeam Agent for Microsoft Windows', win_local:TRUE);

var constraints = [
  { 'min_version' : '2.0', 'fixed_version' : '4.0.2.2208' },
  { 'min_version' : '5.0', 'fixed_version' : '5.0.3.4708' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
