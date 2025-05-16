#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186688);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2023-22523");
  script_xref(name:"IAVA", value:"2023-A-0672");

  script_name(english:"Atlassian Jira Service Management Assets Discovery < 6.2.0 (JSDSERVER-14925)");

  script_set_attribute(attribute:"synopsis", value:
"The Atlassian Jira Service Management Assets Discovery app running on the remote host missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of the Atlassian Jira Service Management Assets Discovery (formerly Insight Discovery) app running on the
remote host is prior to 6.2.0. It is, therefore, affected by a remote code execution vulnerability as referenced in the
JSDSERVER-14925 advisory. The vulnerability exists between the Assets Discovery application and the Assets Discovery 
agent. If exploited by an unauthenticated, remote attacker this vulnerability could allow them to perform privileged RCE
on machines with the Assets Discovery agent installed.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-14925");
  script_set_attribute(attribute:"solution", value:
"Update the Assets Discovery app to 6.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22523");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_management");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:atlassian:assets_discovery");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_jira_assets_discovery_win_installed.nbin");
  script_require_keys("installed_sw/Jira Assets Discovery");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Jira Assets Discovery', win_local:TRUE);

var constraints = [
  {'min_version': '1.0', 'max_version': '3.1.3', 'fixed_version': '6.2.0'},
  {'min_version': '3.1.9', 'max_version': '3.1.11', 'fixed_version': '6.2.0'},
  {'min_version': '6.0.0', 'max_version': '6.1.14', 'fixed_version': '6.2.0'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
