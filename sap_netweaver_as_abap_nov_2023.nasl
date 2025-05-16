#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185737);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/21");

  script_cve_id("CVE-2023-41366");
  script_xref(name:"IAVA", value:"2023-A-0614");

  script_name(english:"SAP NetWeaver AS ABAP Information Disclosure (3362849)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server ABAP and ABAP Platform are affected by an information disclosure vulnerability.
Under certain conditions SAP NetWeaver Application Server ABAP allows an unauthenticated attacker to access unintended
data due to a lack of applied restrictions, which may lead to low impact in confidentiality and no impact on the
integrity and availability of the application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3362849");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41366");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

var app_info = vcf::sap_netweaver_as::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

var fix = 'See vendor advisory';
var constraints = [
  {'equal' : '722', 'fixed_display' : fix },
  {'min_version' : '753', 'max_version': '754', 'fixed_display' : fix },
  {'equal' : '777', 'fixed_display' : fix },
  {'equal' : '785', 'fixed_display' : fix },
  {'equal' : '789', 'fixed_display' : fix },
  {'min_version' : '791', 'max_version': '794', 'fixed_display' : fix }
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE
);