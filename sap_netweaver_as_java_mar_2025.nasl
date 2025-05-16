#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232695);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id("CVE-2025-27431");
  script_xref(name:"IAVA", value:"2025-A-0167");

  script_name(english:"SAP NetWeaver AS Java XSS (March 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver application server is affected by cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server for Java is affected by cross-site scripting vulnerability:

  - User management functionality in SAP NetWeaver Application Server Java is vulnerable to Stored Cross-Site
    Scripting (XSS). This could enable an attacker to inject malicious payload that gets stored and executed 
    when a user accesses the functionality, hence leading to information disclosure or unauthorized data 
    modifications within the scope of victim’s browser. There is no impact on availability. (CVE-2024-22126)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.sap.com/en/my-support/knowledge-base/security-notes-news/march-2025.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccdbfea8");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3567246");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27431");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::sap_netweaver_as::get_app_info();

var constraints = [
  {'equal' : '7.50', 'fixed_display' : 'See vendor advisory' }
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
