#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192028);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-27902");
  script_xref(name:"IAVA", value:"2024-A-0147");

  script_name(english:"SAP NetWeaver AS ABAP XSS (March 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"Applications based on SAP GUI for HTML in SAP NetWeaver AS ABAP - versions 7.89, 7.93, do not sufficiently 
encode user-controlled inputs, resulting in Cross-Site Scripting (XSS) vulnerability. A successful attack can 
allow a malicious attacker to access and modify data through their ability to execute code in a user’s 
browser. There is no impact on the availability of the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.sap.com/en/my-support/knowledge-base/security-notes-news/march-2024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10ff228c");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3377979");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'equal' : '789', 'fixed_display' : fix },
    {'equal' : '793', 'fixed_display' : fix }
  ];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE,
  flags:{'xss':TRUE}
);