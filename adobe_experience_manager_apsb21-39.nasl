#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150491);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2021-28625",
    "CVE-2021-28626",
    "CVE-2021-28627",
    "CVE-2021-28628"
  );
  script_xref(name:"IAVA", value:"2021-A-0269-S");

  script_name(english:"Adobe Experience Manager 6.5.0.0 < 6.5.9.0 Multiple Vulnerabilities (APSB21-39)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Experience Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Experience Manager installed on the remote host is prior to 6.5.9.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB21-39 advisory.

  - Adobe Experience Manager Cloud Service offering, as well as versions 6.5.8.0 (and below) is affected by a
    Server-side Request Forgery. An authenticated attacker could leverage this vulnerability to contact
    systems blocked by the dispatcher. Exploitation of this issue does not require user interaction.
    (CVE-2021-28627)

  - Adobe Experience Manager Cloud Service offering, as well as versions 6.5.8.0 (and below) is affected by a
    Cross-Site Scripting (XSS) vulnerability that could be abused by an attacker to inject malicious scripts
    into vulnerable form fields. Malicious JavaScript may be executed in a victim's browser when they browse
    to the page containing the vulnerable field. (CVE-2021-28625, CVE-2021-28628)

  - Adobe Experience Manager Cloud Service offering, as well as versions 6.5.8.0 (and below) is affected by an
    Improper Authorization vulnerability allowing users to create nodes under a location. An unauthenticated
    attacker could leverage this vulnerability to cause an application denial-of-service. Exploitation of this
    issue does not require user interaction. (CVE-2021-28626)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/experience-manager/apsb21-39.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ab0a049");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Experience Manager version 6.5.9.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28627");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285, 79, 918);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

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
  { 'min_version' : '6.5.0.0', 'fixed_version' : '6.5.9.0' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
