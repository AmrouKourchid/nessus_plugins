#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180573);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/13");

  script_cve_id("CVE-2023-35785");
  script_xref(name:"IAVA", value:"2023-A-0456");

  script_name(english:"ManageEngine ADManager Plus < Build 7201 TFA Bypass");

  script_set_attribute(attribute:"synopsis", value:
"An Active Directory management application running on the remote host is affected by a two factor authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"Zoho ManageEngine ADManager Plus before version 7.2 Build 7201 is affected by a two factor authentication bypass
vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/security/advisory/CVE/CVE-2023-35785.html");
  # https://www.manageengine.com/products/ad-manager/release-notes.html#7201
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c0b299f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADManager Plus version 7.2 build 7201 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_admanager_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_admanager_plus_detect.nbin");
  script_require_keys("installed_sw/ManageEngine ADManager Plus");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('vcf_extras_zoho.inc');
include('http.inc');

var port = get_http_port(default:8080);
var app = 'ManageEngine ADManager Plus';
var app_info = vcf::zoho::fix_parse::get_app_info(app:app, webapp:TRUE, port:port);

var constraints = [
  {'fixed_version': '7201.0', 'fixed_display': '7.2, Build 7201'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
