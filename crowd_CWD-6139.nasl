#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191006);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2023-22521");

  script_name(english:"Atlassian Crowd 3.4.x < 5.1.6 / 5.2.1 RCE (CWD-6139)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Crowd installed on the remote host is affected by a remote execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Crowd installed on the remote host is 3.4.x prior to 5.1.6, or 5.2.x prior to 5.2.1. It is, 
therefore, affected by a remote execution vulnerability. An authenticated, remote attacker can exploit this, to execute 
arbitrary code which has high impact to confidentiality, high impact to integrity, high impact to availability, and 
requires no user interaction.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CWD-6139");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 5.1.6, 5.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22521");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crowd");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("crowd_detect.nasl");
  script_require_keys("www/crowd");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8095);

  exit(0);
}

include('vcf.inc');

var app = 'crowd';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '3.4.0', 'fixed_version' : '5.1.6', 'fixed_display' : '5.1.6 / 5.2.1' },
  { 'min_version' : '5.2.0', 'fixed_version' : '5.2.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

