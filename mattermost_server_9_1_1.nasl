#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185452);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/06");

  script_cve_id(
    "CVE-2023-6202",
    "CVE-2023-40703",
    "CVE-2023-43754",
    "CVE-2023-47168",
    "CVE-2023-48268",
    "CVE-2023-48369"
  );
  script_xref(name:"IAVA", value:"2023-A-0604-S");

  script_name(english:"Mattermost Server < 7.8.13 / 8.x < 8.1.4 / 9.0.x < 9.0.2 / 9.1.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server running on the remote host is prior to 7.8.13, 8.x prior to 8.1.4, 9.0.x prior to
9.0.2 or 9.1.x prior to 9.1.1. It is, therefore, affected by multiple vulnerabilities as referenced in the
MMSA-2023-00218, MMSA-2023-00219, MMSA-2023-00233, MMSA-2023-00241, MMSA-2023-00252 and MMSA-2023-00254 security
advisories.

 - Mattermost fails to limit the amount of data extracted from compressed archives during board import in
   Mattermost Boards allowing an attacker to consume excessive resources, possibly leading to Denial of
   Service, by importing a board using a specially crafted zip (zip bomb). (CVE-2023-48268) (MMSA-2023-00218)

 - Mattermost fails to properly limit the characters allowed in different fields of a block in Mattermost
   Boards allowing a attacker to consume excessive resources, possibly leading to Denial of Service, by
   patching the field of a block using a specially crafted string. (CVE-2023-40709) (MMSA-2023-00219)

 - Mattermost fails to properly check a redirect URL parameter allowing for an open redirect was possible
   when the user clicked 'Back to Mattermost' after providing a invalid custom url scheme in
   /oauth/{service}/mobile_login?redirect_to= (CVE-2023-47168) (MMSA-2023-00252)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 7.8.13, 8.1.4, 9.0.2, 9.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47168");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version' : '7.8.13' },
  { 'min_version' : '8.0', 'fixed_version' : '8.1.4' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.2' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
