#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234844);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id(
    "CVE-2025-42921",
    "CVE-2025-43012",
    "CVE-2025-43013",
    "CVE-2025-43014"
  );
  script_xref(name:"IAVA", value:"2025-A-0292");

  script_name(english:"JetBrains Toolbox App < 2.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JetBrains Toolbox App installed on the remote host is prior to 2.6. It is, therefore, affected by
multiple vulnerabilities:

  - In JetBrains Toolbox App before 2.6 command injection in SSH plugin was possible (CVE-2025-43012)

  - In JetBrains Toolbox App before 2.6 host key verification was missing in SSH plugin (CVE-2025-42921)

  - In JetBrains Toolbox App before 2.6 unencrypted credential transmission during SSH authentication was possible
    (CVE-2025-43013)

  - In JetBrains Toolbox App before 2.6 the SSH plugin established connections without sufficient user confirmation
    (CVE-2025-43014)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.jetbrains.com/privacy-security/issues-fixed/?product=Toolbox+App&version=2.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfc22eac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains Toolbox App version 2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-43012");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:toolbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_toolbox_app_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/JetBrains Toolbox App");

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
      'product': {'name': 'JetBrains Toolbox App', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'fixed_version': '2.6'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
