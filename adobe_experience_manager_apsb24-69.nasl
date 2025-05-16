#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212264);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id(
    "CVE-2024-43711",
    "CVE-2024-43712",
    "CVE-2024-43713",
    "CVE-2024-43714",
    "CVE-2024-43715",
    "CVE-2024-43716",
    "CVE-2024-43717",
    "CVE-2024-43718",
    "CVE-2024-43719",
    "CVE-2024-43720",
    "CVE-2024-43721",
    "CVE-2024-43722",
    "CVE-2024-43723",
    "CVE-2024-43724",
    "CVE-2024-43725",
    "CVE-2024-43726",
    "CVE-2024-43727",
    "CVE-2024-43728",
    "CVE-2024-43729",
    "CVE-2024-43730",
    "CVE-2024-43731",
    "CVE-2024-43732",
    "CVE-2024-43733",
    "CVE-2024-43734",
    "CVE-2024-43735",
    "CVE-2024-43736",
    "CVE-2024-43737",
    "CVE-2024-43738",
    "CVE-2024-43739",
    "CVE-2024-43740",
    "CVE-2024-43742",
    "CVE-2024-43743",
    "CVE-2024-43744",
    "CVE-2024-43745",
    "CVE-2024-43746",
    "CVE-2024-43747",
    "CVE-2024-43748",
    "CVE-2024-43749",
    "CVE-2024-43750",
    "CVE-2024-43751",
    "CVE-2024-43752",
    "CVE-2024-43754",
    "CVE-2024-43755",
    "CVE-2024-52816",
    "CVE-2024-52817",
    "CVE-2024-52818",
    "CVE-2024-52822",
    "CVE-2024-52823",
    "CVE-2024-52824",
    "CVE-2024-52825",
    "CVE-2024-52826",
    "CVE-2024-52827",
    "CVE-2024-52828",
    "CVE-2024-52829",
    "CVE-2024-52830",
    "CVE-2024-52831",
    "CVE-2024-52832",
    "CVE-2024-52834",
    "CVE-2024-52835",
    "CVE-2024-52836",
    "CVE-2024-52837",
    "CVE-2024-52838",
    "CVE-2024-52839",
    "CVE-2024-52840",
    "CVE-2024-52841",
    "CVE-2024-52842",
    "CVE-2024-52843",
    "CVE-2024-52844",
    "CVE-2024-52845",
    "CVE-2024-52846",
    "CVE-2024-52847",
    "CVE-2024-52848",
    "CVE-2024-52849",
    "CVE-2024-52850",
    "CVE-2024-52851",
    "CVE-2024-52852",
    "CVE-2024-52853",
    "CVE-2024-52854",
    "CVE-2024-52855",
    "CVE-2024-52857",
    "CVE-2024-52858",
    "CVE-2024-52859",
    "CVE-2024-52860",
    "CVE-2024-52861",
    "CVE-2024-52862",
    "CVE-2024-52864",
    "CVE-2024-52865",
    "CVE-2024-52991",
    "CVE-2024-52992",
    "CVE-2024-52993",
    "CVE-2024-53960"
  );
  script_xref(name:"IAVA", value:"2024-A-0785");

  script_name(english:"Adobe Experience Manager 6.5.0 < 6.5.22 Multiple Vulnerabilities (APSB24-69)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5.22. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB24-69 advisory.

  - Adobe Experience Manager versions 6.5.21 and earlier are affected by an Improper Authorization
    vulnerability that could result in a Security feature bypass. An attacker could leverage this
    vulnerability to bypass security measures and gain unauthorized access. Exploitation of this issue does
    not require user interaction. (CVE-2024-43729, CVE-2024-43731)

  - Adobe Experience Manager versions 6.5.21 and earlier are affected by a stored Cross-Site Scripting (XSS)
    vulnerability that could be abused by an attacker to inject malicious scripts into vulnerable form fields.
    Malicious JavaScript may be executed in a victim's browser when they browse to the page containing the
    vulnerable field. (CVE-2024-43718, CVE-2024-43725, CVE-2024-43726, CVE-2024-43727, CVE-2024-43728,
    CVE-2024-43730, CVE-2024-43734, CVE-2024-43736, CVE-2024-43737, CVE-2024-43739, CVE-2024-43740,
    CVE-2024-43742, CVE-2024-43743, CVE-2024-43744, CVE-2024-43746, CVE-2024-43747, CVE-2024-43748,
    CVE-2024-43749, CVE-2024-43750, CVE-2024-43751, CVE-2024-43752, CVE-2024-52816, CVE-2024-52817,
    CVE-2024-52818, CVE-2024-52824, CVE-2024-52825, CVE-2024-52826, CVE-2024-52827, CVE-2024-52828,
    CVE-2024-52829, CVE-2024-52830, CVE-2024-52832, CVE-2024-52834, CVE-2024-52835, CVE-2024-52836,
    CVE-2024-52841, CVE-2024-52842, CVE-2024-52843, CVE-2024-52845, CVE-2024-52846, CVE-2024-52847,
    CVE-2024-52848, CVE-2024-52849, CVE-2024-52850, CVE-2024-52851, CVE-2024-52852, CVE-2024-52853,
    CVE-2024-52854, CVE-2024-52855, CVE-2024-52857, CVE-2024-52858, CVE-2024-52859, CVE-2024-52861,
    CVE-2024-52862, CVE-2024-52864, CVE-2024-52865, CVE-2024-52991, CVE-2024-52992, CVE-2024-52993,
    CVE-2024-53960)

  - Adobe Experience Manager versions 6.5.21 and earlier are affected by a DOM-based Cross-Site Scripting
    (XSS) vulnerability that could allow an attacker to execute arbitrary code in the context of the victim's
    browser. This issue occurs when data from a user-controllable source is improperly sanitized before being
    used in the Document Object Model (DOM) of a web page, leading to the execution of malicious scripts.
    Exploitation of this issue requires user interaction, such as tricking a victim into clicking a link or
    navigating to a malicious website. (CVE-2024-43712)

  - Adobe Experience Manager versions 6.5.21 and earlier are affected by a DOM-based Cross-Site Scripting
    (XSS) vulnerability that could be exploited by an attacker to execute arbitrary code in the context of the
    victim's browser session. By manipulating a DOM element through a crafted URL or user input, the attacker
    can inject malicious scripts that run when the page is rendered. This type of attack requires user
    interaction, as the victim would need to access a manipulated URL or page with the malicious script.
    (CVE-2024-43713, CVE-2024-52822)

  - Adobe Experience Manager versions 6.5.21 and earlier are affected by a DOM-based Cross-Site Scripting
    (XSS) vulnerability that could be exploited by an attacker to execute arbitrary code in the context of the
    victim's browser session. By manipulating a DOM element through a crafted URL or user input, the attacker
    can inject malicious scripts that run when the page is rendered. This type of attack requires user
    interaction, as the victim would need to visit a malicious link or input data into a vulnerable page.
    (CVE-2024-43714)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb24-69.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef4e99e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.22 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43755");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-43729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 284, 285, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:experience_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.5.0', 'fixed_version' : '6.5.22' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
