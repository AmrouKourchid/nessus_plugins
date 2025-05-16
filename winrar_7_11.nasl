#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234002);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-31334");
  script_xref(name:"IAVA", value:"2025-A-0227");

  script_name(english:"WinRAR < 7.11 Mark of the Web Bypass (CVE-2025-31334)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed which is affected by a mark of the web bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WinRAR, an archive manager for Windows, whose reported version is prior to 7.11. It is,
therefore, affected by a vulnerability:

  - Issue that bypasses the 'Mark of the Web' security warning function for files when opening a symbolic link that
    points to an executable file exists in WinRAR versions prior to 7.11. If a symbolic link specially crafted by an
    attacker is opened on the affected product, arbitrary code may be executed. (CVE-2025-31334)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://jvn.jp/en/jp/JVN59547048/");
  script_set_attribute(attribute:"see_also", value:"https://www.rarlab.com/rarnew.htm");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WinRAR version 7.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31334");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rarlab:winrar");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winrar_win_installed.nbin");
  script_require_keys("installed_sw/RARLAB WinRAR", "SMB/Registry/Enumerated");

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
      'product': {'name': 'RARLAB WinRAR', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'fixed_version': '7.11'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
