#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204778);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/29");

  script_cve_id("CVE-2024-21687");
  script_xref(name:"IAVA", value:"2024-A-0437");

  script_name(english:"Atlassian Bamboo < 9.2.16 /  < 9.6.4 File Inclusion (CVE-2024-21687)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Bamboo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Bamboo installed on the remote host is prior to 9.2.16 or 9.6.4. It is, therefore, affected by
a file inclusion allows an authenticated attacker to get the application to display the contents of a local file, or 
execute a different files already stored locally on the server which has high impact to confidentiality, high impact to 
integrity, no impact to availability, and requires no user interaction. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BAM-25822");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Bamboo version 9.2.16, 9.6.4, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21687");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bamboo");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'max_version' : '9.0.4', 'fixed_display' : '9.6.4 LTS recommended or 9.2.16 LTS'},
  { 'min_version' : '9.1.0', 'max_version' : '9.1.3', 'fixed_display' : '9.6.4 LTS recommended or 9.2.16 LTS'},
  { 'min_version' : '9.2.0', 'max_version' : '9.2.15', 'fixed_version' : '9.2.16'},
  { 'min_version' : '9.3.0', 'max_version' : '9.3.6', 'fixed_display' : '9.6.4 LTS recommended'},
  { 'min_version' : '9.4.0', 'max_version' : '9.4.3', 'fixed_display' : '9.6.4 LTS recommended'},
  { 'min_version' : '9.5.0', 'max_version' : '9.5.4', 'fixed_display' : '9.6.4 LTS recommended'},
  { 'min_version' : '9.6.0', 'max_version' : '9.6.3', 'fixed_verison' : '9.6.4'},
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
