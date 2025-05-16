#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152487);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2021-36061", "CVE-2021-36062", "CVE-2021-36063");
  script_xref(name:"IAVB", value:"2021-B-0045-S");

  script_name(english:"Adobe Connect <= 11.2.2 Multiple Vulnerabilities (APSB21-66)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect installed on the remote host is prior to 11.2.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the apsb21-66 advisory.

  - Adobe Connect version 11.2.2 (and earlier) is affected by a Reflected Cross-site Scripting vulnerability
    that could be abused by an attacker to inject malicious scripts into vulnerable form fields. Malicious
    JavaScript may be executed in a victim's browser when they browse to the page containing the vulnerable
    field. (CVE-2021-36063)

  - Adobe Connect version 11.2.2 (and earlier) is affected by a secure design principles violation
    vulnerability via the 'pbMode' parameter. An unauthenticated attacker could leverage this vulnerability to
    edit or delete recordings on the Connect environment. Exploitation of this issue requires user interaction
    in that a victim must publish a link of a Connect recording. (CVE-2021-36061)

  - Adobe Connect version 11.2.2 (and earlier) is affected by a Reflected Cross-site Scripting vulnerability
    that could be abused by an attacker to inject malicious scripts into vulnerable form fields. If an
    attacker is able to convince a victim to visit a URL referencing a vulnerable page, malicious JavaScript
    content may be executed within the context of the victim's browser. (CVE-2021-36062)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb21-66.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 11.2.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36063");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(657, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:connect");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '11.0.0', 'max_version' : '11.2.2', 'fixed_version' : '11.2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
