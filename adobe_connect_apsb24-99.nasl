#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212244);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/15");

  script_cve_id(
    "CVE-2024-49550",
    "CVE-2024-54032",
    "CVE-2024-54034",
    "CVE-2024-54035",
    "CVE-2024-54036",
    "CVE-2024-54037",
    "CVE-2024-54038",
    "CVE-2024-54039",
    "CVE-2024-54040",
    "CVE-2024-54041",
    "CVE-2024-54042",
    "CVE-2024-54043",
    "CVE-2024-54044",
    "CVE-2024-54045",
    "CVE-2024-54046",
    "CVE-2024-54047",
    "CVE-2024-54048",
    "CVE-2024-54049",
    "CVE-2024-54050",
    "CVE-2024-54051"
  );
  script_xref(name:"IAVB", value:"2024-B-0192");

  script_name(english:"Adobe Connect <= 11.4.7 Multiple Vulnerabilities (APSB24-99)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect installed on the remote host is prior to 11.4.9. It is, therefore, affected by multiple
vulnerabilities as referenced in the apsb24-99 advisory.

  - Adobe Connect versions 12.6, 11.4.7 and earlier are affected by a stored Cross-Site Scripting (XSS)
    vulnerability that could be abused by an attacker to inject malicious scripts into vulnerable form fields.
    Malicious JavaScript may be executed in a victim's browser when they browse to the page containing the
    vulnerable field. (CVE-2024-54032, CVE-2024-54036, CVE-2024-54039, CVE-2024-54040, CVE-2024-54041)

  - Adobe Connect versions 12.6, 11.4.7 and earlier are affected by a reflected Cross-Site Scripting (XSS)
    vulnerability. If an attacker is able to convince a victim to visit a URL referencing a vulnerable page,
    malicious JavaScript content may be executed within the context of the victim's browser. (CVE-2024-49550,
    CVE-2024-54034, CVE-2024-54042, CVE-2024-54043, CVE-2024-54044, CVE-2024-54045, CVE-2024-54046,
    CVE-2024-54047, CVE-2024-54048, CVE-2024-54049)

  - Adobe Connect versions 12.6, 11.4.7 and earlier are affected by a DOM-based Cross-Site Scripting (XSS)
    vulnerability that could be exploited by an attacker to execute arbitrary code in the context of the
    victim's browser session. By manipulating a DOM element through a crafted URL or user input, the attacker
    can inject malicious scripts that run when the page is rendered. This type of attack requires user
    interaction, as the victim would need to visit a malicious link or input data into a compromised form.
    (CVE-2024-54037)

  - Adobe Connect versions 12.6, 11.4.7 and earlier are affected by a URL Redirection to Untrusted Site ('Open
    Redirect') vulnerability. An attacker could leverage this vulnerability to redirect users to malicious
    websites. Exploitation of this issue requires user interaction. (CVE-2024-54050, CVE-2024-54051)

  - Adobe Connect versions 12.6, 11.4.7 and earlier are affected by an Improper Access Control vulnerability
    that could result in a Security feature bypass. An attacker could leverage this vulnerability to bypass
    security measures and gain unauthorized access. Exploitation of this issue does not require user
    interaction. (CVE-2024-54038)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb24-99.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 11.4.9 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54036");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284, 285, 601, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '11.0.0', 'max_version' : '11.4.7', 'fixed_version' : '11.4.9' },
  { 'min_version' : '12.0', 'max_version' : '12.6', 'fixed_version' : '12.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
