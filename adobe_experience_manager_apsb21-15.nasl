#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149434);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2021-21083", "CVE-2021-21084");
  script_xref(name:"IAVA", value:"2021-A-0234-S");

  script_name(english:"Adobe Experience Manager 6.3.0.0 < 6.4.8.4 / 6.5.0.0 < 6.5.8.0 Multiple Vulnerabilities (APSB21-15)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.4.8.4, 6.5.8.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB21-15 advisory.

  - AEM's Cloud Service offering, as well as versions 6.5.7.0 (and below), 6.4.8.3 (and below) and 6.3.3.8
    (and below) are affected by a stored Cross-Site Scripting (XSS) vulnerability that could be abused by an
    attacker to inject malicious scripts into vulnerable form fields. Malicious JavaScript may be executed in
    a victim's browser when they browse to the page containing the vulnerable field. (CVE-2021-21084)

  - AEM's Cloud Service offering, as well as versions 6.5.7.0 (and below), 6.4.8.3 (and below) and 6.3.3.8
    (and below) are affected by an Improper Access Control vulnerability. An unauthenticated attacker could
    leverage this vulnerability to cause an application denial-of-service in the context of the current user.
    (CVE-2021-21083)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb21-15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9e9f74f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.4.8.4, 6.5.8.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21084");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.3.0.0', 'fixed_version' : '6.4.8.4' },
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.8.0' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
