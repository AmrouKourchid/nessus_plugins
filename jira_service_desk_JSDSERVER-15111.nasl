#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192524);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2023-2976");

  script_name(english:"Atlassian Jira Service Management Data Center and Server < 5.4.16 / 5.5.x < 5.12.3 / 5.13.x < 5.13.1 / 5.14.0 (JSDSERVER-15111)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira Service Management Data Center and Server host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Service Management Data Center and Server running on the remote host is affected by a
vulnerability as referenced in the JSDSERVER-15111 advisory.

  - Use of Java's default temporary directory for file creation in `FileBackedOutputStream` in Google Guava
    versions 1.0 to 31.1 on Unix systems and Android Ice Cream Sandwich allows other users and apps on the
    machine with access to the default Java temporary directory to be able to access the files created by the
    class. Even though the security vulnerability is fixed in version 32.0.0, we recommend using version
    32.0.1 as version 32.0.0 breaks some functionality under Windows. (CVE-2023-2976)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-15111");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Service Management Data Center and Server version 5.4.16, 5.12.3, 5.13.1, 5.14.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2976");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "jira_service_desk_installed_win.nbin", "jira_service_desk_installed_nix.nbin");
  script_require_keys("installed_sw/JIRA Service Desk Application");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JIRA Service Desk Application');

var constraints = [
  { 'min_version' : '1.0.0',  'max_version' : '4.22.6', 'fixed_display' : '5.14.0 / 5.12.4 / 5.4.17' },
  { 'equal' : '5.0.0',                                  'fixed_display' : '5.14.0 / 5.12.4 / 5.4.17' },
  { 'min_version' : '5.1.0',  'max_version' : '5.1.1',  'fixed_display' : '5.14.0 / 5.12.4 / 5.4.17' },
  { 'min_version' : '5.2.0',  'max_version' : '5.2.1',  'fixed_display' : '5.14.0 / 5.12.4 / 5.4.17' },
  { 'min_version' : '5.3.0',  'max_version' : '5.3.1',  'fixed_display' : '5.14.0 / 5.12.4 / 5.4.17' },
  { 'min_version' : '5.4.0',  'max_version' : '5.4.15', 'fixed_display' : '5.14.0 / 5.12.4 / 5.4.17' },
  { 'min_version' : '5.5.0',  'max_version' : '5.5.1',  'fixed_display' : '5.14.0 / 5.12.4' },
  { 'min_version' : '5.6.0',  'max_version' : '5.6.2',  'fixed_display' : '5.14.0 / 5.12.4' },
  { 'min_version' : '5.7.0',  'max_version' : '5.7.2',  'fixed_display' : '5.14.0 / 5.12.4' },
  { 'min_version' : '5.8.0',  'max_version' : '5.8.2',  'fixed_display' : '5.14.0 / 5.12.4' },
  { 'min_version' : '5.9.0',  'max_version' : '5.9.2',  'fixed_display' : '5.14.0 / 5.12.4' },
  { 'min_version' : '5.10.0', 'max_version' : '5.10.2', 'fixed_display' : '5.14.0 / 5.12.4' },
  { 'min_version' : '5.11.0', 'max_version' : '5.11.3', 'fixed_display' : '5.14.0 / 5.12.4' },
  { 'min_version' : '5.12.0', 'max_version' : '5.12.2', 'fixed_display' : '5.14.0 / 5.12.4 / 5.4.17' },
  { 'equal' :       '5.13.0',                           'fixed_display' : '5.13.1 / 5.14.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
