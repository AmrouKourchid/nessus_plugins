#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200354);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id(
    "CVE-2024-20769",
    "CVE-2024-20784",
    "CVE-2024-22243",
    "CVE-2024-26029",
    "CVE-2024-26036",
    "CVE-2024-26037",
    "CVE-2024-26039",
    "CVE-2024-26049",
    "CVE-2024-26053",
    "CVE-2024-26054",
    "CVE-2024-26055",
    "CVE-2024-26057",
    "CVE-2024-26058",
    "CVE-2024-26060",
    "CVE-2024-26066",
    "CVE-2024-26068",
    "CVE-2024-26070",
    "CVE-2024-26071",
    "CVE-2024-26072",
    "CVE-2024-26074",
    "CVE-2024-26075",
    "CVE-2024-26077",
    "CVE-2024-26078",
    "CVE-2024-26081",
    "CVE-2024-26082",
    "CVE-2024-26083",
    "CVE-2024-26085",
    "CVE-2024-26086",
    "CVE-2024-26088",
    "CVE-2024-26089",
    "CVE-2024-26090",
    "CVE-2024-26091",
    "CVE-2024-26092",
    "CVE-2024-26093",
    "CVE-2024-26095",
    "CVE-2024-26110",
    "CVE-2024-26111",
    "CVE-2024-26113",
    "CVE-2024-26114",
    "CVE-2024-26115",
    "CVE-2024-26116",
    "CVE-2024-26117",
    "CVE-2024-26121",
    "CVE-2024-26123",
    "CVE-2024-26126",
    "CVE-2024-26127",
    "CVE-2024-34119",
    "CVE-2024-34120",
    "CVE-2024-34128",
    "CVE-2024-34141",
    "CVE-2024-34142",
    "CVE-2024-36141",
    "CVE-2024-36142",
    "CVE-2024-36143",
    "CVE-2024-36144",
    "CVE-2024-36146",
    "CVE-2024-36147",
    "CVE-2024-36148",
    "CVE-2024-36149",
    "CVE-2024-36150",
    "CVE-2024-36151",
    "CVE-2024-36152",
    "CVE-2024-36153",
    "CVE-2024-36154",
    "CVE-2024-36155",
    "CVE-2024-36156",
    "CVE-2024-36157",
    "CVE-2024-36158",
    "CVE-2024-36159",
    "CVE-2024-36160",
    "CVE-2024-36161",
    "CVE-2024-36162",
    "CVE-2024-36163",
    "CVE-2024-36164",
    "CVE-2024-36165",
    "CVE-2024-36166",
    "CVE-2024-36167",
    "CVE-2024-36168",
    "CVE-2024-36169",
    "CVE-2024-36170",
    "CVE-2024-36171",
    "CVE-2024-36172",
    "CVE-2024-36173",
    "CVE-2024-36174",
    "CVE-2024-36175",
    "CVE-2024-36176",
    "CVE-2024-36177",
    "CVE-2024-36178",
    "CVE-2024-36179",
    "CVE-2024-36180",
    "CVE-2024-36181",
    "CVE-2024-36182",
    "CVE-2024-36183",
    "CVE-2024-36184",
    "CVE-2024-36185",
    "CVE-2024-36186",
    "CVE-2024-36187",
    "CVE-2024-36188",
    "CVE-2024-36189",
    "CVE-2024-36190",
    "CVE-2024-36191",
    "CVE-2024-36192",
    "CVE-2024-36193",
    "CVE-2024-36194",
    "CVE-2024-36195",
    "CVE-2024-36196",
    "CVE-2024-36197",
    "CVE-2024-36198",
    "CVE-2024-36199",
    "CVE-2024-36200",
    "CVE-2024-36201",
    "CVE-2024-36202",
    "CVE-2024-36203",
    "CVE-2024-36204",
    "CVE-2024-36205",
    "CVE-2024-36206",
    "CVE-2024-36207",
    "CVE-2024-36208",
    "CVE-2024-36209",
    "CVE-2024-36210",
    "CVE-2024-36211",
    "CVE-2024-36212",
    "CVE-2024-36213",
    "CVE-2024-36214",
    "CVE-2024-36215",
    "CVE-2024-36216",
    "CVE-2024-36217",
    "CVE-2024-36218",
    "CVE-2024-36219",
    "CVE-2024-36220",
    "CVE-2024-36221",
    "CVE-2024-36222",
    "CVE-2024-36223",
    "CVE-2024-36224",
    "CVE-2024-36225",
    "CVE-2024-36226",
    "CVE-2024-36227",
    "CVE-2024-36228",
    "CVE-2024-36229",
    "CVE-2024-36230",
    "CVE-2024-36231",
    "CVE-2024-36232",
    "CVE-2024-36233",
    "CVE-2024-36234",
    "CVE-2024-36235",
    "CVE-2024-36236",
    "CVE-2024-36238",
    "CVE-2024-36239",
    "CVE-2024-41839",
    "CVE-2024-41841",
    "CVE-2024-41842",
    "CVE-2024-41843",
    "CVE-2024-41844",
    "CVE-2024-41845",
    "CVE-2024-41846",
    "CVE-2024-41847",
    "CVE-2024-41848",
    "CVE-2024-41849",
    "CVE-2024-41875",
    "CVE-2024-41876",
    "CVE-2024-45153",
    "CVE-2024-49523",
    "CVE-2024-49524"
  );
  script_xref(name:"IAVA", value:"2024-A-0449-S");
  script_xref(name:"IAVA", value:"2024-A-0349-S");

  script_name(english:"Adobe Experience Manager 6.5.0 < 6.5.21 Multiple Vulnerabilities (APSB24-28)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5.21. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB24-28 advisory.

  - Adobe Experience Manager versions 6.5.20 and earlier are affected by an Improper Access Control
    vulnerability that could result in a Security feature bypass. An attacker could leverage this
    vulnerability to bypass security measures and gain disclose information. Exploitation of this issue does
    not require user interaction. (CVE-2024-26029)

  - Applications that use UriComponentsBuilder to parse an externally provided URL (e.g. through a query
    parameter) AND perform validation checks on the host of the parsed URL may be vulnerable to a open
    redirect https://cwe.mitre.org/data/definitions/601.html attack or to a SSRF attack if the URL is used
    after passing validation checks. (CVE-2024-22243)

  - Adobe Experience Manager versions 6.5.20 and earlier are affected by a stored Cross-Site Scripting (XSS)
    vulnerability that could be abused by an attacker to inject malicious scripts into vulnerable form fields.
    Malicious JavaScript may be executed in a victim's browser when they browse to the page containing the
    vulnerable field. (CVE-2024-20769, CVE-2024-20784, CVE-2024-26036, CVE-2024-26054, CVE-2024-26060,
    CVE-2024-26066, CVE-2024-26068, CVE-2024-26070, CVE-2024-26071, CVE-2024-26074, CVE-2024-26075,
    CVE-2024-26077, CVE-2024-26078, CVE-2024-26081, CVE-2024-26082, CVE-2024-26083, CVE-2024-26085,
    CVE-2024-26088, CVE-2024-26092, CVE-2024-26095, CVE-2024-26110, CVE-2024-26121, CVE-2024-26123,
    CVE-2024-34119, CVE-2024-34120, CVE-2024-36142, CVE-2024-36143, CVE-2024-36144, CVE-2024-36146,
    CVE-2024-36147, CVE-2024-36149, CVE-2024-36150, CVE-2024-36152, CVE-2024-36153, CVE-2024-36154,
    CVE-2024-36155, CVE-2024-36156, CVE-2024-36157, CVE-2024-36158, CVE-2024-36159, CVE-2024-36160,
    CVE-2024-36161, CVE-2024-36162, CVE-2024-36163, CVE-2024-36164, CVE-2024-36165, CVE-2024-36166,
    CVE-2024-36167, CVE-2024-36168, CVE-2024-36169, CVE-2024-36170, CVE-2024-36171, CVE-2024-36172,
    CVE-2024-36173, CVE-2024-36174, CVE-2024-36175, CVE-2024-36176, CVE-2024-36177, CVE-2024-36178,
    CVE-2024-36179, CVE-2024-36180, CVE-2024-36182, CVE-2024-36185, CVE-2024-36186, CVE-2024-36187,
    CVE-2024-36188, CVE-2024-36189, CVE-2024-36191, CVE-2024-36192, CVE-2024-36193, CVE-2024-36194,
    CVE-2024-36195, CVE-2024-36196, CVE-2024-36198, CVE-2024-36199, CVE-2024-36200, CVE-2024-36201,
    CVE-2024-36202, CVE-2024-36203, CVE-2024-36204, CVE-2024-36205, CVE-2024-36207, CVE-2024-36208,
    CVE-2024-36209, CVE-2024-36212, CVE-2024-36213, CVE-2024-36214, CVE-2024-36215, CVE-2024-36217,
    CVE-2024-36218, CVE-2024-36219, CVE-2024-36221, CVE-2024-36225, CVE-2024-36232, CVE-2024-41842,
    CVE-2024-41843, CVE-2024-41844, CVE-2024-41845, CVE-2024-41846, CVE-2024-41875, CVE-2024-49523)

  - Adobe Experience Manager versions 6.5.20 and earlier Answer: are affected by a DOM-based Cross-Site
    Scripting (XSS) vulnerability. This vulnerability could allow an attacker to execute arbitrary JavaScript
    code in the context of the victim's browser session. Exploitation of this issue typically requires user
    interaction, such as convincing a user to click on a specially crafted link or to submit a malicious form.
    (CVE-2024-26037, CVE-2024-36183, CVE-2024-36229)

  - Adobe Experience Manager versions 6.5.20 and earlier Answer: are affected by a DOM-based Cross-Site
    Scripting (XSS) vulnerability. This vulnerability could allow an attacker to execute arbitrary JavaScript
    code in the context of the victim's browser session. Exploitation of this issue requires user interaction,
    such as convincing a victim to click on a specially crafted link or to submit a form that triggers the
    vulnerability. (CVE-2024-26039, CVE-2024-26053, CVE-2024-36197, CVE-2024-36228)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb24-28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8ac37ef");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.21 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26029");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 284, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

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
  { 'min_version' : '6.5.0', 'fixed_version' : '6.5.21' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
