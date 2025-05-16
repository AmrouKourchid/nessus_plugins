#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190890);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/01");

  script_cve_id("CVE-2024-21682");
  script_xref(name:"IAVA", value:"2024-A-0111");

  script_name(english:"Atlassian Jira Service Management Assets Discovery < 6.2.1 (JSDSERVER-15067)");

  script_set_attribute(attribute:"synopsis", value:
"The Atlassian Jira Service Management Assets Discovery app running on the remote host missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of the Atlassian Jira Service Management Assets Discovery (formerly Insight Discovery) app running on the
host is affected by a vulnerability as referenced in the JSDSERVER-15067 advisory.

  - This High severity Injection vulnerability was introduced in Assets Discovery 1.0 - 6.2.0 (all versions).
    Assets Discovery, which can be downloaded via Atlassian Marketplace, is a network scanning tool that can
    be used with or without an agent with Jira Service Management Cloud, Data Center or Server. It detects
    hardware and software that is connected to your local network and extracts detailed information about
    each asset. This data can then be imported into Assets in Jira Service Management to help you manage all
    of the devices and configuration items within your local network. An authenticated attacker could modify
    the actions taken by a system call which has high impact to confidentiality, high impact to integrity,
    high impact to availability, and requires no user interaction.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-15067");
  script_set_attribute(attribute:"solution", value:
"Update the Assets Discovery app to 6.2.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_management");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:atlassian:assets_discovery");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_jira_assets_discovery_win_installed.nbin");
  script_require_keys("installed_sw/Jira Assets Discovery");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Jira Assets Discovery');

var constraints = [ { 'fixed_version' : '6.2.1' } ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
