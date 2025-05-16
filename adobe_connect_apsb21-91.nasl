#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154144);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id("CVE-2021-40719", "CVE-2021-40721");
  script_xref(name:"IAVB", value:"2021-B-0058-S");

  script_name(english:"Adobe Connect <= 11.2.3 Multiple Arbitrary Code Execution Vulnerabilities (APSB21-91)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple arbitrary code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Connect installed on the remote host is prior to 11.3.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the apsb21-91 advisory.

  - Adobe Connect version 11.2.3 (and earlier) is affected by a reflected Cross-Site Scripting (XSS)
    vulnerability. If an attacker is able to convince a victim to visit a URL referencing a vulnerable page,
    malicious JavaScript content may be executed within the context of the victim's browser. (CVE-2021-40721)

  - Adobe Connect version 11.2.3 (and earlier) is affected by a Deserialization of Untrusted Data
    vulnerability to achieve arbitrary method invocation when AMF messages are deserialized on an Adobe
    Connect server. An attacker can leverage this to execute remote code execution on the server.
    (CVE-2021-40719)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/connect/apsb21-91.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Connect version 11.3.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40719");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-40721");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(502, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

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
  { 'min_version' : '11.0.0', 'max_version' : '11.2.3', 'fixed_version' : '11.3.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
