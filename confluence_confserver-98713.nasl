#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213296);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id("CVE-2023-45859");

  script_name(english:"Atlassian Confluence 3.7.x < 7.19.22 / 7.20.x < 8.5.9 / 8.6.x < 8.9.0 / 9.2.0 (CONFSERVER-98713)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-98713 advisory.

  - In Hazelcast through 4.1.10, 4.2 through 4.2.8, 5.0 through 5.0.5, 5.1 through 5.1.7, 5.2 through 5.2.4,
    and 5.3 through 5.3.2, some client operations don't check permissions properly, allowing authenticated
    users to access data stored in the cluster. (CVE-2023-45859)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-98713");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.22, 8.5.9, 8.9.0, 9.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'min_version' : '3.7.0', 'fixed_version' : '7.19.22' },
  { 'min_version' : '7.20.0', 'fixed_version' : '8.5.9' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.9.0', 'fixed_display' : '8.9.0 / 9.2.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
