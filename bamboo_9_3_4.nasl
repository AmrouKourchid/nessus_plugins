#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191551);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/30");

  script_cve_id("CVE-2023-22516");

  script_name(english:"Atlassian Bamboo 8.1 < 9.2.7 / 9.3 < 9.3.4 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Bamboo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Bamboo installed on the remote host is prior to 9.2.7 or 9.3.4. It is, therefore, affected by
a remote code execution vulnerability. This allows an authenticated attacker to modify the actions taken by a system
call and execute arbitrary code which has high impact to confidentiality, high impact to integrity, high impact to
availability, and no user interaction.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BAM-25168");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Bamboo version 9.2.7, 9.3.4, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bamboo");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bamboo_detect.nbin");
  script_require_keys("installed_sw/bamboo");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8085);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app = 'bamboo';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:8085);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '8.1', 'fixed_version' : '9.2.7'},
  { 'min_version' : '9.3', 'fixed_version' : '9.3.4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
