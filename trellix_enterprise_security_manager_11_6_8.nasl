#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186467);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/01");

  script_cve_id("CVE-2023-6670");
  script_xref(name:"IAVB", value:"2023-B-0094");

  script_name(english:"Trellix Enterprise Security Manager < 11.6.8 SSRF");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a server-side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Trellix Enterprise Security Manager running on the remote web server is prior to 11.6.8. It is,
therefore, affected by a server-side request forgery (SSRF) vulnerability. Due to a flaw in the certificate validation
functionality, a remote, authenticated attacker can upload arbitrary content, potentially altering configuration.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kcm.trellix.com/corporate/index?page=content&id=SB10413");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trellix Enterprise Security Manager 11.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:trellix:enterprise_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:enterprise_security_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("enterprise_security_manager_detect.nbin");
  script_require_keys("installed_sw/Trellix Enterprise Security Manager");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Trellix Enterprise Security Manager', webapp:TRUE, port:port);

var constraints = [
  { 'fixed_version': '11.6.8' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

