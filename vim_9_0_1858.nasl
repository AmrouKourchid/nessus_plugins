#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180543);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id("CVE-2023-4752");
  script_xref(name:"IAVB", value:"2023-B-0066-S");

  script_name(english:"Vim < 9.0.1858");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"Use After Free flaw in vim prior to 9.0.1858.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/vim/vim/commit/ee9166eb3b41846661a39b662dc7ebe8b5e15139
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5766863e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.0.1858 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4752");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.0.1858' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
