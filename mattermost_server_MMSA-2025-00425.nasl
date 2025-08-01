#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214349);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2025-20088");
  script_xref(name:"IAVA", value:"2025-A-0017-S");

  script_name(english:"Mattermost Server 9.11.x < 9.11.6 / 10.0.x < 10.0.4 / 10.1.x < 10.1.4 / 10.2.x < 10.2.1 DoS (MMSA-2025-00425)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server installed on the remote host is 9.11.x prior to 9.11.6, 10.0.x prior to 
10.0.4, 10.1.x prior to 10.1.4, or 10.2.x prior to 10.2.1. It is, therefore, affected by a denial of 
service vulnerability due to a failure to properly validate post props which allows a malicious 
authenticated user to cause a crash via a malicious post.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 9.11.6, 10.0.4,  10.1.4, 10.2.1, 10.3.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(754);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'Mattermost Server', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '9.11', 'max_version' : '9.11.5', 'fixed_version' : '9.11.6' },
  { 'min_version' : '10.0', 'max_version' : '10.0.3', 'fixed_version' : '10.0.4' },
  { 'min_version' : '10.1', 'max_version' : '10.1.3', 'fixed_version' : '10.1.4' },
  { 'min_version' : '10.2', 'fixed_version' : '10.2.1', 'fixed_display' : '10.2.1 or 10.3.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
