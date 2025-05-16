#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186429);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/09");

  script_cve_id("CVE-2023-48706");
  script_xref(name:"IAVA", value:"2023-A-0650-S");

  script_name(english:"Vim < 9.0.2121");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"Vim is a UNIX editor that, prior to version 9.0.2121, has a heap-use-after-free vulnerability. When executing a `:s` 
command for the very first time and using a sub-replace-special atom inside the substitution part, it is possible that 
the recursive `:s` call causes free-ing of memory which may later then be accessed by the initial `:s` command. The 
user must intentionally execute the payload and the whole process is a bit tricky to do since it seems to work only 
reliably for the very first :s command. It may also cause a crash of Vim. Version 9.0.2121 contains a fix for this 
issue.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/vim/vim/security/advisories/GHSA-c8qm-x72m-q53q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21f12ec4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.0.2121 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48706");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.0.2121' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
