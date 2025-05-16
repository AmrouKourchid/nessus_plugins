#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137367);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2020-9643",
    "CVE-2020-9644",
    "CVE-2020-9645",
    "CVE-2020-9647",
    "CVE-2020-9648",
    "CVE-2020-9651"
  );
  script_xref(name:"IAVA", value:"2020-A-0253-S");

  script_name(english:"Adobe Experience Manager 6.0 < 6.5 Multiple Vulnerabilities (APSB20-31)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB20-31 advisory.

  - Adobe Experience Manager versions 6.5 and earlier have a blind server-side request forgery (ssrf)
    vulnerability. Successful exploitation could lead to sensitive information disclosure. (CVE-2020-9645)

  - Adobe Experience Manager versions 6.5 and earlier have a server-side request forgery (ssrf) vulnerability.
    Successful exploitation could lead to sensitive information disclosure. (CVE-2020-9643)

  - Adobe Experience Manager versions 6.5 and earlier have a cross-site scripting (dom-based) vulnerability.
    Successful exploitation could lead to arbitrary javascript execution in the browser. (CVE-2020-9647)

  - Adobe Experience Manager versions 6.5 and earlier have a cross-site scripting vulnerability. Successful
    exploitation could lead to arbitrary javascript execution in the browser. (CVE-2020-9648)

  - Adobe Experience Manager versions 6.5 and earlier have a cross-site scripting (stored) vulnerability.
    Successful exploitation could lead to arbitrary javascript execution in the browser. (CVE-2020-9644)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb20-31.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22dc4755");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_experience_manager_http_detect.nbin");
  script_require_keys("installed_sw/Adobe Experience Manager");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:4502);
var app_info = vcf::get_app_info(app:'Adobe Experience Manager', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '6.0', 'fixed_version' : '6.5' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
