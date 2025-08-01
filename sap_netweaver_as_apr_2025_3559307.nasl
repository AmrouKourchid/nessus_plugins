#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234227);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-26653");

  script_name(english:"SAP NetWeaver AS ABAP XSS (3559307)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote SAP NetWeaver ABAP server may be affected by an information disclosure vulnerability. 
SAP NetWeaver Application Server ABAP does not sufficiently encode user-controlled inputs, leading 
to Stored Cross-Site Scripting (XSS) vulnerability. This enables an attacker, without requiring any 
privileges, to inject malicious JavaScript into a website. When a user visits the compromised page, 
the injected script gets executed, potentially compromising the confidentiality and integrity within 
the scope of the victim’s browser. Availability is not impacted.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
    # https://support.sap.com/en/my-support/knowledge-base/security-notes-news/april-2025.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92dca101");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3559307");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26653");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
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
  {'equal':'7.22',	'fixed_display': fix},
  {'equal':'7.53',	'fixed_display': fix},
  {'equal':'7.54',	'fixed_display': fix},
  {'equal':'7.77',	'fixed_display': fix},
  {'equal':'7.89',	'fixed_display': fix},
  {'equal':'7.93',	'fixed_display': fix},
  {'equal':'9.14',	'fixed_display': fix},
  
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE,
  flags: {'xss':true}
);
