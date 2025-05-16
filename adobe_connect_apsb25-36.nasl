#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235875);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id(
    "CVE-2025-30314",
    "CVE-2025-30315",
    "CVE-2025-30316",
    "CVE-2025-43567"
  );

  script_name(english:"Adobe Connect <= 12.8 Multiple Vulnerabilities (APSB25-36)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect installed on the remote host is prior to 12.9. It is, therefore, affected by multiple
vulnerabilities as referenced in the apsb25-36 advisory.

  - Adobe Connect versions 12.8 and earlier are affected by a reflected Cross-Site Scripting (XSS)
    vulnerability that could be abused by an attacker to inject malicious scripts into vulnerable form fields.
    Malicious JavaScript may be executed in a victim's browser when they browse to the page containing the
    vulnerable field. A successful attacker can abuse this to achieve session takeover, increasing the
    confidentiality and integrity impact as high. (CVE-2025-43567)

  - Adobe Connect versions 12.8 and earlier are affected by a stored Cross-Site Scripting (XSS) vulnerability
    that could be abused by an attacker to inject malicious scripts into vulnerable form fields. Malicious
    JavaScript may be executed in a victim's browser when they browse to the page containing the vulnerable
    field. (CVE-2025-30314, CVE-2025-30315)

  - Adobe Connect versions 12.8 and earlier are affected by a stored Cross-Site Scripting (XSS) vulnerability
    that could be abused by a low privileged attacker to inject malicious scripts into vulnerable form fields.
    Malicious JavaScript may be executed in a victim's browser when they browse to the page containing the
    vulnerable field. (CVE-2025-30316)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb25-36.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 12.9 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-43567");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '12.0', 'max_version' : '12.8', 'fixed_version' : '12.9' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
