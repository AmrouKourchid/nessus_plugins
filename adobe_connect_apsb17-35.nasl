#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104572);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2017-11287",
    "CVE-2017-11288",
    "CVE-2017-11289",
    "CVE-2017-11290",
    "CVE-2017-11291"
  );
  script_bugtraq_id(101838);

  script_name(english:"Adobe Connect <= 9.6.2 Multiple Vulnerabilities (APSB17-35)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect installed on the remote host is prior to 9.7.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the apsb17-35 advisory.

  - An issue was discovered in Adobe Connect 9.6.2 and earlier versions. A Server-Side Request Forgery (SSRF)
    vulnerability exists that could be abused to bypass network access controls. (CVE-2017-11291)

  - An issue was discovered in Adobe Connect 9.6.2 and earlier versions. A reflected cross-site scripting
    vulnerability exists that can result in information disclosure. (CVE-2017-11287, CVE-2017-11288,
    CVE-2017-11289)

  - An issue was discovered in Adobe Connect 9.6.2 and earlier versions. A UI Redress (or Clickjacking)
    vulnerability exists. This issue has been resolved by adding a feature that enables Connect administrators
    to protect users from UI redressing (or clickjacking) attacks. (CVE-2017-11290)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb17-35.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 9.7.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/15");

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
  { 'min_version' : '9.0.0', 'max_version' : '9.6.2', 'fixed_version' : '9.7.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
