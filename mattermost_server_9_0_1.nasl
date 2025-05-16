#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185731);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/16");

  script_cve_id("CVE-2023-5967", "CVE-2023-5968", "CVE-2023-5969");
  script_xref(name:"IAVA", value:"2023-A-0613-S");

  script_name(english:"Mattermost Server < 7.8.12 / 8.0.x < 8.0.4 / 8.1.x < 8.1.3 / 9.0.0 Multiple Vulnerabilities (MMSA-2023-00240) (MMSA-2023-00242) (MMSA-2023-00246)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server running on the remote host is prior to 7.8.12, 8.0.x prior to 8.0.3, 8.1.x prior to
8.1.3 or 9.0.0. It is, therefore, affected by multiple vulnerabilities:

 - Mattermost fails to properly validate requests to the Calls plugin, allowing an attacker sending a request
   without a User Agent header to cause a panic and crash the Calls plugin (CVE-2023-5967)

 - Mattermost fails to properly sanitize the user object when updating the username, resulting in the password
   hash being included in the response body. (CVE-2023-5968)

 - Mattermost fails to properly sanitize the request to /api/v4/redirect_location allowing an attacker,
   sending a specially crafted request to /api/v4/redirect_location, to fill up the memory due to caching large
   items. (CVE-2023-5969)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 7.8.12, 8.0.4, 8.1.3, 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'Mattermost Server', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '7.8.12' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.4' },
  { 'min_version' : '8.1', 'fixed_version' : '8.1.3' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
