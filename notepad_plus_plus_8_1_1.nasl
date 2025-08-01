#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205291);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/12");

  script_cve_id("CVE-2023-6401");
  script_xref(name:"IAVA", value:"2024-A-0463");

  script_name(english:"Notepad++ < 8.1.1 Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The text editor on the remote Windows host is affected by a arbitary code execution.");
  script_set_attribute(attribute:"description", value:
"The version of Notepad++ installed on the remote host is prior to 8.1.1. It is, therefore, affected by a arbitary code 
execution vulnerability in the dbghelp.exe file, allowing a attacker with local access to abuse the uncontrolled search 
path to execute arbitrary code and gain access.
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://notepad-plus-plus.org/news/v857-released-fix-security-issues/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Notepad++ 8.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6401");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:notepad-plus-plus:notepad\+\+");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("notepad_plus_plus_win_installed.nbin");
  script_require_keys("installed_sw/Notepad++", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Notepad++');

var constraints = [{'fixed_version':'8.1.1'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);

