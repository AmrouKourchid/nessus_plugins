##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162744);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2021-42340");

  script_name(english:"Atlassian Jira < 8.13.18 / 8.14.0 < 8.20.6 / 8.21.0 (JRASERVER-73070)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira installed on the remote host is prior to 8.13.18 / 8.14.0 < 8.20.6 / 8.21.0. It is, therefore, affected by a
vulnerability as referenced in the JRASERVER-73070 advisory.

  - Denial of service via an OutOfMemoryError (Tomcat CVE-2021-42340) (CVE-2021-42340)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-73070");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.13.18, 8.20.6, 8.21.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42340");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

# if on LTS release 8.13.x needs the 8.13.18 patch.
# else if on LTS release 8.20.x needs the 8.20.6 patch
# if else upgrade to 8.21.0
var constraints = [
  { 'fixed_version' : '8.13.18', 'fixed_display' : '8.13.18 / 8.20.6 / 8.21.0' },
  { 'min_version' : '8.14.0', 'fixed_version' : '8.20.6', 'fixed_display' : '8.20.6 / 8.21.0' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
