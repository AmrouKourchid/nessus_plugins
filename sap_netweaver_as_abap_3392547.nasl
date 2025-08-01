#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186936);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/20");

  script_cve_id("CVE-2023-49581");
  script_xref(name:"IAVA", value:"2023-A-0692");

  script_name(english:"SAP NetWeaver AS ABAP Information Disclosure (3392547)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by a Information Disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"SAP GUI for Windows and SAP GUI for Java allow an unauthenticated attacker to access information 
which would otherwise be restricted and confidential. In addition, this vulnerability allows the 
unauthenticated attacker to write data to a database table. By doing so the attacker could 
increase response times of the AS ABAP, leading to mild impact on availability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://blogs.sap.com/2023/12/13/sap-security-patch-day-december-2023/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?289f7199");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.support.sap.com/#/notes/3392547");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49581");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'min_version' : '700', 'max_version' : '702', 'fixed_display' : fix },
    {'equal' : '731', 'fixed_display' : fix },
    {'equal' : '740', 'fixed_display' : fix },
    {'min_version' : '750', 'max_version' : '758', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  abap:TRUE
);
