#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168696);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id(
    "CVE-2022-30679",
    "CVE-2022-35693",
    "CVE-2022-35694",
    "CVE-2022-35695",
    "CVE-2022-35696",
    "CVE-2022-42345",
    "CVE-2022-42346",
    "CVE-2022-42348",
    "CVE-2022-42349",
    "CVE-2022-42350",
    "CVE-2022-42351",
    "CVE-2022-42352",
    "CVE-2022-42354",
    "CVE-2022-42356",
    "CVE-2022-42357",
    "CVE-2022-42360",
    "CVE-2022-42362",
    "CVE-2022-42364",
    "CVE-2022-42365",
    "CVE-2022-42366",
    "CVE-2022-42367",
    "CVE-2022-44462",
    "CVE-2022-44463",
    "CVE-2022-44465",
    "CVE-2022-44466",
    "CVE-2022-44467",
    "CVE-2022-44468",
    "CVE-2022-44469",
    "CVE-2022-44470",
    "CVE-2022-44471",
    "CVE-2022-44473",
    "CVE-2022-44474",
    "CVE-2022-44488",
    "CVE-2022-44510"
  );
  script_xref(name:"IAVA", value:"2022-A-0529-S");

  script_name(english:"Adobe Experience Manager 6.5.0.0 < 6.5.15.0 Multiple Vulnerabilities (APSB22-59)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5.15.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB22-59 advisory.

  - Adobe Experience Manager version 6.5.14 (and earlier) is affected by a reflected Cross-Site Scripting
    (XSS) vulnerability. If a low-privileged attacker is able to convince a victim to visit a URL referencing
    a vulnerable page, malicious JavaScript content may be executed within the context of the victim's
    browser. (CVE-2022-30679, CVE-2022-35693, CVE-2022-35694, CVE-2022-35695, CVE-2022-35696, CVE-2022-42345,
    CVE-2022-42346, CVE-2022-42348, CVE-2022-42349, CVE-2022-42350, CVE-2022-42352, CVE-2022-42354,
    CVE-2022-42356, CVE-2022-42357, CVE-2022-42360, CVE-2022-42362, CVE-2022-42364, CVE-2022-42365,
    CVE-2022-42366, CVE-2022-42367, CVE-2022-44462, CVE-2022-44463, CVE-2022-44465, CVE-2022-44466,
    CVE-2022-44467, CVE-2022-44468, CVE-2022-44469, CVE-2022-44470, CVE-2022-44471, CVE-2022-44473,
    CVE-2022-44474, CVE-2022-44510)

  - Adobe Experience Manager version 6.5.14 (and earlier) is affected by an Incorrect Authorization
    vulnerability that could result in a security feature bypass. A low-privileged attacker could leverage
    this vulnerability to disclose low level confidentiality information. Exploitation of this issue does not
    require user interaction. (CVE-2022-42351)

  - Adobe Experience Manager version 6.5.14 (and earlier) is affected by a URL Redirection to Untrusted Site
    ('Open Redirect') vulnerability. A low-privilege authenticated attacker could leverage this vulnerability
    to redirect users to malicious websites. Exploitation of this issue requires user interaction.
    (CVE-2022-44488)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb22-59.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff15f91");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.15.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44510");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 284, 601);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.15.0' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
