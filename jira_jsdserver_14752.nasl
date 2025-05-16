#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186229);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2022-42004");

  script_name(english:"Atlassian Jira Service Management Data Center and Server < 4.20.27 / 5.4.x < 5.4.11 (JSDSERVER-14752)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira Service Management Data Center and Server (Jira Service Desk) host is missing a security 
update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Service Management Data Center and Server (Jira Service Desk) running on the remote 
host is affected by a vulnerability as referenced in the JSDSERVER-14752 advisory.

  - In FasterXML jackson-databind before 2.13.4, resource exhaustion can occur because of a lack of a check in
    BeanDeserializer._deserializeFromArray to prevent use of deeply nested arrays. An application is
    vulnerable only with certain customized choices for deserialization. (CVE-2022-42004)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-14752");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Service Management Data Center and Server version 4.20.27, 5.4.11 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42004");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
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
  { 'min_version' : '4.20.0','fixed_version' : '4.20.27' },
  { 'min_version' : '5.4.0', 'fixed_version' : '5.4.11' },
  { 'min_version' : '5.5.1', 'fixed_version' : '5.5.2', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.6.0', 'fixed_version' : '5.6.1', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.7.0', 'fixed_version' : '5.7.1', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.8.0', 'fixed_version' : '5.8.1', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.9.0', 'fixed_version' : '5.9.1', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.10.0', 'fixed_version' : '5.10.1', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
