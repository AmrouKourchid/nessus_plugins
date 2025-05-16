#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235059);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2025-46432", "CVE-2025-46433", "CVE-2025-46618");
  script_xref(name:"IAVA", value:"2025-A-0305");

  script_name(english:"JetBrains TeamCity < 2025.03.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of JetBrains TeamCity installed on the remote host is prior to 2025.03.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the TeamCity_2025_04 advisory.

  - In JetBrains TeamCity before 2025.03.1 base64-encoded credentials could be exposed in build logs
    (CVE-2025-46432)

  - In JetBrains TeamCity before 2025.03.1 improper path validation in loggingPreset parameter was possible
    (CVE-2025-46433)

  - In JetBrains TeamCity before 2025.03.1 stored XSS was possible on Data Directory tab (CVE-2025-46618)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jetbrains.com/privacy-security/issues-fixed/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains TeamCity version 2025.03.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-46433");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:teamcity");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_teamcity_web_detect.nbin", "jetbrains_teamcity_win_installed.nbin", "jetbrains_teamcity_nix_installed.nbin");
  script_require_keys("installed_sw/JetBrains TeamCity");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'JetBrains TeamCity', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints' : [
        {'fixed_version': '2025.03.1'}
      ]
    }
  ]
};

var vdf_result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING, flags:{'xss':TRUE});
vdf::handle_check_and_report_errors(vdf_result:vdf_result);
