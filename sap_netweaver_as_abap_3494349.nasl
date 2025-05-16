#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205614);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id("CVE-2024-41734");
  script_xref(name:"IAVA", value: "2024-A-0497");

  script_name(english:"SAP NetWeaver AS ABAP Missing Authorization (3494349)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"Due to missing authorization check in SAP NetWeaver Application Server ABAP and ABAP Platform, an authenticated attacker
could call an underlying transaction, which leads to disclosure of user related information. There is no impact on
integrity or availability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3494349");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41734");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sap_netweaver_as_web_detect.nbin");
  script_require_keys("installed_sw/SAP Netweaver Application Server (AS)", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000, 50000);

  exit(0);
}

include('vcf_extras_sap.inc');

var app_info = vcf::sap_netweaver_as::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
    {'equal':'700', 'fixed_display':'SAPKB70042'},
    {'equal':'701', 'fixed_display':'SAPKB70127'},
    {'equal':'702', 'fixed_display':'SAPKB70227'},
    {'equal':'731', 'fixed_display':'SAPKB73136'},
    {'equal':'740', 'fixed_display':'SAPKB74032'},
    {'equal':'750', 'fixed_display':'SAPK-75031INSAPBASIS'},
    {'equal':'751', 'fixed_display':'SAPK-75119INSAPBASIS'},
    {'equal':'752', 'fixed_display':'SAPK-75215INSAPBASIS'},
    {'equal':'753', 'fixed_display':'SAPK-75313INSAPBASIS'},
    {'equal':'754', 'fixed_display':'SAPK-75411INSAPBASIS'},
    {'equal':'755', 'fixed_display':'SAPK-75509INSAPBASIS'},
    {'equal':'756', 'fixed_display':'SAPK-75607INSAPBASIS'},
    {'equal':'757', 'fixed_display':'SAPK-75705INSAPBASIS'},
    {'equal':'758', 'fixed_display':'SAPK-75803INSAPBASIS'},
    {'equal':'912', 'fixed_display':'SAPK-91203INSAPBASIS'}
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE
);
