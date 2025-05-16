#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210048);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id(
    "CVE-2024-50574",
    "CVE-2024-50575",
    "CVE-2024-50576",
    "CVE-2024-50577",
    "CVE-2024-50578",
    "CVE-2024-50579",
    "CVE-2024-50580",
    "CVE-2024-50581",
    "CVE-2024-50582"
  );
  script_xref(name:"IAVA", value:"2024-A-0697-S");

  script_name(english:"JetBrains YouTrack < 2024.3.47707 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of JetBrains YouTrack installed on the remote host is prior to 2024.3.47707. It is, therefore, affected by
multiple vulnerabilities as referenced in the vendor advisory.

  - Potential ReDoS exploit was possible via email header parsing in Helpdesk functionality (CVE-2024-50574)

  - Reflected XSS was possible in Widget API. (CVE-2024-50575)

  - Stored XSS was possible via vendor URL in App manifest. (CVE-2024-50576)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.jetbrains.com/privacy-security/issues-fixed/?product=YouTrack&version=2024.3.47707
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec48f98a");
  script_set_attribute(attribute:"solution", value:
"Upgrade JetBrains YouTrack 2024.3.47707 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50579");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:youtrack");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  { 'fixed_version' : '2024.3.47707'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
