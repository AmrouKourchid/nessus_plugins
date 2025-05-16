#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101395);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2017-3101", "CVE-2017-3102", "CVE-2017-3103");
  script_bugtraq_id(99517, 99518, 99521);

  script_name(english:"Adobe Connect <= 9.6.1 Multiple Vulnerabilities (APSB17-22)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect installed on the remote host is prior to 9.6.2. It is, therefore, affected by multiple
vulnerabilities as referenced in the apsb17-22 advisory.

  - Adobe Connect versions 9.6.1 and earlier have a clickjacking vulnerability. Successful exploitation could
    lead to a clickjacking attack. (CVE-2017-3101)

  - Adobe Connect versions 9.6.1 and earlier have a reflected cross-site scripting vulnerability. Successful
    exploitation could lead to a reflected cross-site scripting attack. (CVE-2017-3102)

  - Adobe Connect versions 9.6.1 and earlier have a stored cross-site scripting vulnerability. Successful
    exploitation could lead to a stored cross-site scripting attack. (CVE-2017-3103)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb17-22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 9.6.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3101");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '9.0.0', 'max_version' : '9.6.1', 'fixed_version' : '9.6.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
