#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202627);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2022-41966");
  script_xref(name:"IAVA", value:"2024-A-0412");

  script_name(english:"Atlassian Jira Service Management Data Center and Server < 5.4.18 / 5.5.x < 5.8.0 / 5.12.0 (JSDSERVER-15436)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira Service Management Data Center and Server (Jira Service Desk) host is missing a security
update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Service Management Data Center and Server (Jira Service Desk) running on the remote host
is affected by a vulnerability as referenced in the JSDSERVER-15436 advisory.

  - XStream serializes Java objects to XML and back again. Versions prior to 1.4.20 may allow a remote
    attacker to terminate the application with a stack overflow error, resulting in a denial of service only
    via manipulation the processed input stream. The attack uses the hash code implementation for collections
    and maps to force recursive hash calculation causing a stack overflow. This issue is patched in version
    1.4.20 which handles the stack overflow and raises an InputManipulationException instead. A potential
    workaround for users who only use HashMap or HashSet and whose XML refers these only as default map or
    set, is to change the default implementation of java.util.Map and java.util per the code example in the
    referenced advisory. However, this implies that your application does not care about the implementation of
    the map and all elements are comparable. (CVE-2022-41966)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-15436");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Service Management Data Center and Server version 5.4.18, 5.8.0, 5.12.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41966");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '0.0', 'max_version' : '4.21', 'fixed_display' : '5.4.18 / 5.8.0 / 5.12.0' },
  { 'min_version' : '4.22', 'max_version' : '4.22.6', 'fixed_display' : '5.4.18 / 5.8.0 / 5.12.0' },
  { 'equal' : '5.0', 'fixed_display' : '5.4.18 / 5.8.0 / 5.12.0' },
  { 'min_version' : '5.1', 'max_version' : '5.1.1', 'fixed_display' : '5.4.18 / 5.8.0 / 5.12.0' },
  { 'min_version' : '5.2', 'max_version' : '5.2.1', 'fixed_display' : '5.4.18 / 5.8.0 / 5.12.0' },
  { 'min_version' : '5.3', 'max_version' : '5.3.1', 'fixed_display' : '5.4.18 / 5.8.0 / 5.12.0' },
  { 'min_version' : '5.4', 'max_version' : '5.4.17', 'fixed_display' : '5.4.18 / 5.8.0 / 5.12.0' },
  { 'min_version' : '5.5', 'max_version' : '5.5.1', 'fixed_display' : '5.8.0 / 5.12.0' },
  { 'min_version' : '5.6', 'max_version' : '5.6.2', 'fixed_display' : '5.8.0 / 5.12.0' },
  { 'min_version' : '5.7', 'max_version' : '5.7.2', 'fixed_display' : '5.8.0 / 5.12.0' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
