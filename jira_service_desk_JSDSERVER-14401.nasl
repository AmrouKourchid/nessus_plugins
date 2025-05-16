#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183513);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2019-13990");
  script_xref(name:"IAVA", value:"2023-A-0570");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Atlassian JIRA Service Desk < 4.20.26 / 5.4.x < 5.4.10 / 5.5.x < 5.7.2 / 5.8.x < 5.8.2 / 5.9.x < 5.9.2 / 5.10.x < 5.10.1 (JSDSERVER-14401)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian JIRA Service Desk host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian JIRA Service Desk Server running on the remote host is affected by a vulnerability as
referenced in the JSDSERVER-14401 advisory.

  - XXE (XML External Entity Injection) in Jira Service Management Data Center and Server - CVE-2019-13990
    (CVE-2019-13990)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-14401");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA Service Desk version 4.20.26, 5.4.10, 5.7.2, 5.8.2, 5.9.2, 5.10.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13990");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "jira_service_desk_installed_win.nbin", "jira_service_desk_installed_nix.nbin");
  script_require_keys("installed_sw/JIRA Service Desk Application");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JIRA Service Desk Application');

var constraints = [
  { 'min_version' : '4.20.0', 'fixed_version' : '4.20.26' },
  { 'min_version' : '5.4.0', 'fixed_version' : '5.4.10' },
  { 'min_version' : '5.5.1', 'fixed_version' : '5.7.2' },
  { 'min_version' : '5.8.0', 'fixed_version' : '5.8.2' },
  { 'min_version' : '5.9.0', 'fixed_version' : '5.9.2' },
  { 'min_version' : '5.10.0', 'fixed_version' : '5.10.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
