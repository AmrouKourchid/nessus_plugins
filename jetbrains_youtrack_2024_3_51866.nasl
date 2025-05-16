#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212126);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id("CVE-2024-54153", "CVE-2024-54154", "CVE-2024-54155");
  script_xref(name:"IAVA", value:"2024-A-0779-S");

  script_name(english:"JetBrains YouTrack 2024.3.51866 Multiple Vulnerabilities (2024_3_51866)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of JetBrains YouTrack installed on the remote host is prior to 2024.3.51866. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2024_3_51866 advisory.

  - In JetBrains YouTrack before 2024.3.51866, unauthenticated database backup download was possible via
    a vulnerable query parameter (CVE-2024-54153)

  - In JetBrains YouTrack before 2024.3.51866, system takeover was possible through path traversal in plugin
    sandbox (CVE-2024-54154)

  - In JetBrains YouTrack before 2024.3.51866, improper access control allowed listing of project names during
    app import without authentication (CVE-2024-54155)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jetbrains.com/privacy-security/issues-fixed/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains YouTrack version 2024.3.51866 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:youtrack");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_youtrack_win_installed.nbin", "jetbrains_youtrack_nix_installed.nbin");
  script_require_keys("installed_sw/JetBrains YouTrack");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JetBrains YouTrack');

var constraints = [
  { 'fixed_version' : '2024.3.51866' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
