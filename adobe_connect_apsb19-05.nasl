#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121110);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2018-19718");
  script_bugtraq_id(106469);
  script_xref(name:"IAVB", value:"2019-B-0003-S");

  script_name(english:"Adobe Connect <= 9.8.1 Exposure Of The Privileges Granted To A Session Vulnerability (APSB19-05)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
a exposure of the privileges granted to a session vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect installed on the remote host is prior to 10.1.0. It is, therefore, affected by a
vulnerability as referenced in the apsb19-05 advisory.

  - Adobe Connect versions 9.8.1 and earlier have a session token exposure vulnerability. Successful
    exploitation could lead to exposure of the privileges granted to a session. (CVE-2018-19718)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb19-05.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 10.1.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_connect_detect.nbin");
  script_require_keys("installed_sw/Adobe Connect");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:'Adobe Connect', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '9.0.0', 'max_version' : '9.8.1', 'fixed_version' : '10.1.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
