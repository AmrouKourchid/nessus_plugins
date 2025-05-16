#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191909);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id(
    "CVE-2024-20760",
    "CVE-2024-20768",
    "CVE-2024-20799",
    "CVE-2024-20800",
    "CVE-2024-26028",
    "CVE-2024-26030",
    "CVE-2024-26031",
    "CVE-2024-26032",
    "CVE-2024-26033",
    "CVE-2024-26034",
    "CVE-2024-26035",
    "CVE-2024-26038",
    "CVE-2024-26040",
    "CVE-2024-26041",
    "CVE-2024-26042",
    "CVE-2024-26043",
    "CVE-2024-26044",
    "CVE-2024-26045",
    "CVE-2024-26050",
    "CVE-2024-26051",
    "CVE-2024-26052",
    "CVE-2024-26056",
    "CVE-2024-26059",
    "CVE-2024-26061",
    "CVE-2024-26062",
    "CVE-2024-26063",
    "CVE-2024-26064",
    "CVE-2024-26065",
    "CVE-2024-26067",
    "CVE-2024-26069",
    "CVE-2024-26073",
    "CVE-2024-26080",
    "CVE-2024-26094",
    "CVE-2024-26096",
    "CVE-2024-26101",
    "CVE-2024-26102",
    "CVE-2024-26103",
    "CVE-2024-26104",
    "CVE-2024-26105",
    "CVE-2024-26106",
    "CVE-2024-26107",
    "CVE-2024-26118",
    "CVE-2024-26119",
    "CVE-2024-26120",
    "CVE-2024-26124",
    "CVE-2024-26125",
    "CVE-2024-41877",
    "CVE-2024-41878"
  );
  script_xref(name:"IAVA", value:"2024-A-0158-S");
  script_xref(name:"IAVA", value:"2024-A-0349-S");

  script_name(english:"Adobe Experience Manager 6.5.0.0 < 6.5.20.0 Multiple Vulnerabilities (APSB24-05)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5.20.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB24-05 advisory.

  - Adobe Experience Manager versions 6.5.19 and earlier are affected by a DOM-based Cross-Site Scripting
    (XSS) vulnerability. This vulnerability could allow an attacker to inject and execute arbitrary JavaScript
    code within the context of the user's browser session. Exploitation of this issue requires user
    interaction, such as convincing a victim to click on a malicious link. (CVE-2024-41878)

  - Adobe Experience Manager versions 6.5.19 and earlier are affected by a stored Cross-Site Scripting (XSS)
    vulnerability that could be abused by an attacker to inject malicious scripts into vulnerable form fields.
    Malicious JavaScript may be executed in a victim's browser when they browse to the page containing the
    vulnerable field. (CVE-2024-20760, CVE-2024-20768, CVE-2024-20799, CVE-2024-26028, CVE-2024-26030,
    CVE-2024-26031, CVE-2024-26033, CVE-2024-26034, CVE-2024-26035, CVE-2024-26038, CVE-2024-26040,
    CVE-2024-26041, CVE-2024-26043, CVE-2024-26045, CVE-2024-26050, CVE-2024-26051, CVE-2024-26052,
    CVE-2024-26056, CVE-2024-26059, CVE-2024-26061, CVE-2024-26062, CVE-2024-26065, CVE-2024-26067,
    CVE-2024-26069, CVE-2024-26073, CVE-2024-26094, CVE-2024-26096, CVE-2024-26120, CVE-2024-26124,
    CVE-2024-26125, CVE-2024-41877)

  - Adobe Experience Manager versions 6.5.19 and earlier are affected by a DOM-based Cross-Site Scripting
    (XSS) vulnerability that could be abused by an attacker to inject malicious scripts into vulnerable web
    pages. Malicious JavaScript may be executed in a victim's browser when they browse to the page containing
    the vulnerable script. This could result in arbitrary code execution in the context of the victim's
    browser. Exploitation of this issue requires user interaction. (CVE-2024-26032)

  - Adobe Experience Manager versions 6.5.19 and earlier are affected by a DOM-based Cross-Site Scripting
    (XSS) vulnerability that could be abused by an attacker to inject malicious scripts into vulnerable web
    pages. Malicious JavaScript may be executed in a victim's browser when they browse to the page containing
    the vulnerable script. This could result in arbitrary code execution in the context of the victim's
    browser. (CVE-2024-26042)

  - Adobe Experience Manager versions 6.5.19 and earlier are affected by a DOM-based Cross-Site Scripting
    (XSS) vulnerability that could be abused by an attacker to inject malicious scripts into a webpage.
    Malicious JavaScript may be executed in a victim's browser when they browse to the page containing the
    vulnerable script. This could result in arbitrary code execution in the context of the victim's browser.
    (CVE-2024-26044)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb24-05.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fa49f98");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.20.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26119");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-41878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 284, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.20.0' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
