#%NASL_MIN_LEVEL 80900
##
# Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234038);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-20570");
  script_xref(name:"IAVA", value:"2025-A-0241");

  script_name(english:"Security Update for Microsoft Visual Studio Code (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Visual Studio Code installed on the remote Windows host is prior to 1.99.1. It is, therefore,
affected by an unspecified elevation of privilege vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-20570
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecad86e5");
  # https://code.visualstudio.com/updates/v1_99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c41dc859");
  script_set_attribute(attribute:"solution", value:
"Update to Microsoft Visual Studio Code 1.99.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20570");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_code_installed.nbin", "microsoft_visual_studio_code_win_user_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio Code", "SMB/Registry/Enumerated");

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
      'product': {'name': 'Microsoft Visual Studio Code', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'fixed_version': '1.99.1'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
