#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186418);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/09");

  script_cve_id("CVE-2023-48231");
  script_xref(name:"IAVA", value:"2023-A-0650-S");

  script_name(english:"Vim < 9.0.2106");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"Vim is an open source command line text editor. When closing a window, vim may try to access already freed window 
structure. Exploitation beyond crashing the application has not been shown to be viable. This issue has been addressed 
in release version 9.0.2106.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/vim/vim/security/advisories/GHSA-8g46-v9ff-c765
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b3fa6fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.0.2106 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/16");
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
  { 'fixed_version' : '9.0.2106' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
