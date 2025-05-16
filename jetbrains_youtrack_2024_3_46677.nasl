#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209232);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2024-48902");
  script_xref(name:"IAVA", value:"2024-A-0648-S");

  script_name(english:"JetBrains YouTrack < 2024.3.46677 Improper Access Control");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JetBrains YouTrack installed on the remote host is prior to 2024.3.46677. It is, therefore, affected by a
vulnerability as referenced in the 2024_3_46677 advisory.

  - In JetBrains YouTrack before 2024.3.46677 improper access control allowed users with project update
    permission to delete applications via API (CVE-2024-48902)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jetbrains.com/privacy-security/issues-fixed/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains YouTrack version 2024.3.46677 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-48902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:youtrack");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_youtrack_win_installed.nbin", "jetbrains_youtrack_nix_installed.nbin");
  script_require_keys("installed_sw/JetBrains YouTrack");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JetBrains YouTrack');

var constraints = [
  { 'fixed_version' : '2024.3.46677' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
