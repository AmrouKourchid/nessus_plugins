#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234617);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2025-29768");
  script_xref(name:"IAVA", value:"2025-A-0278");

  script_name(english:"Vim < 9.1.1198 Argument Injection (GHSA-693p-m996-3rmf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Vim installed on the remote host is prior to 9.1.1198. It is, therefore, affected by a vulnerability as
referenced in the GHSA-693p-m996-3rmf advisory.

  - Vim, a text editor, is vulnerable to potential data loss with zip.vim and special crafted zip files in 
    versions prior to 9.1.1198. The impact is medium because a user must be made to view such an archive with 
    Vim and then press 'x' on such a strange filename. The issue has been fixed as of Vim patch v9.1.1198. 
    (CVE-2025-29768)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/vim/vim/security/advisories/GHSA-693p-m996-3rmf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?929e82e6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.1.1198 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29768");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match': {'os': 'windows'}}
  ],
  'checks': [
    {
      'product': {'name': 'Vim', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints' : [
        { 'fixed_version' : '9.1.1198' }
      ]
    }
  ]
};

var vdf_result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result:vdf_result);