#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208723);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/03");

  script_cve_id(
    "CVE-2024-47161",
    "CVE-2024-47948",
    "CVE-2024-47949",
    "CVE-2024-47950",
    "CVE-2024-47951"
  );
  script_xref(name:"IAVA", value:"2024-A-0635-S");

  script_name(english:"JetBrains TeamCity < 2024.7.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of JetBrains TeamCity installed on the remote host is prior to 2024.7.3. It is, therefore, affected by
multiple vulnerabilities:

  - In JetBrains TeamCity before 2024.07.3 password could be exposed via Sonar runner REST API (CVE-2024-47161)

  - In JetBrains TeamCity before 2024.07.3 path traversal leading to information disclosure was possible 
    via server backups (CVE-2024-47948)

  - In JetBrains TeamCity before 2024.07.3 path traversal allowed backup file write 
    to arbitrary location (CVE-2024-47949)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.jetbrains.com/privacy-security/issues-fixed/?product=TeamCity
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48be73f6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains TeamCity version 	2024.7.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47949");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:teamcity");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_teamcity_web_detect.nbin", "jetbrains_teamcity_win_installed.nbin", "jetbrains_teamcity_nix_installed.nbin");
  script_require_keys("installed_sw/JetBrains TeamCity");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JetBrains TeamCity');

var constraints = [
  { 'fixed_version' : '2024.07.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
