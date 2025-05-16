#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234223);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-27437");
  script_xref(name:"IAVA", value:"2025-A-0230");

  script_name(english:"SAP NetWeaver AS ABAP Access Control (3568778)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by an access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote SAP NetWeaver ABAP server may be affected by an access control vulnerability.  A Missing Authorization 
Check vulnerability exists in the Virus Scanner Interface of SAP NetWeaver Application Server ABAP. Because of this, 
an attacker authenticated as a non-administrative user can initiate a transaction, allowing them to access but not 
modify non-sensitive data without further authorization and with no effect on availability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.sap.com/en/my-support/knowledge-base/security-notes-news/april-2025.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92dca101");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3568778");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27437");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

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

var app_info = vcf::sap_netweaver_as::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var fix = 'See vendor advisory';
var constraints = [
  {'min_version':'700', 'max_version': '702',	'fixed_display': fix},
  {'equal':'731',	'fixed_display': fix},
  {'equal':'740',	'fixed_display': fix},
  {'min_version':'750', 'max_version': '758',	'fixed_display': fix}
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE
);
