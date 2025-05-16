#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188067);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2022-44729");

  script_name(english:"Atlassian Jira Service Management Data Center and Server < 4.20.30 / 5.4.x < 5.4.15 / 5.7.x < 5.12.2 (JSDSERVER-14958)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Jira Service Management Data Center and Server (Jira Service Desk) host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Jira Service Management Data Center and Server (Jira Service Desk) running on the remote host is 
affected by a vulnerability as referenced in the JSDSERVER-14958 advisory.

  - Server-Side Request Forgery (SSRF) vulnerability in Apache Software Foundation Apache XML Graphics
    Batik.This issue affects Apache XML Graphics Batik: 1.16. On version 1.16, a malicious SVG could trigger
    loading external resources by default, causing resource consumption or in some cases even information
    disclosure. Users are recommended to upgrade to version 1.17 or later. (CVE-2022-44729)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-14958");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Service Management Data Center and Server version 4.20.30, 5.4.15, 5.12.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

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
  { 'min_version' : '4.20.0', 'fixed_version' : '4.20.30' },
  { 'min_version' : '5.4.0', 'fixed_version' : '5.4.15' },
  { 'min_version' : '5.7.0', 'fixed_version' : '5.7.3', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.8.0', 'fixed_version' : '5.8.3', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.9.0', 'fixed_version' : '5.9.3', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.10.0', 'fixed_version' : '5.10.3', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.11.0', 'fixed_version' : '5.11.4', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '5.12.0', 'fixed_version' : '5.12.2'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
