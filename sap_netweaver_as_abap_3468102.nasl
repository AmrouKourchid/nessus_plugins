#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205613);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id("CVE-2024-41732");
  script_xref(name:"IAVA", value:"2024-A-0497");

  script_name(english:"SAP NetWeaver AS ABAP Improper Access Control (3468102)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver ABAP server may be affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"SAP NetWeaver Application Server ABAP allows an unauthenticated attacker to craft a URL link that could bypass
allowlist controls. Depending on the web applications provided by this server, the attacker might inject CSS code or
links into the web application that could allow the attacker to read or modify information. There is no impact on
availability of application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3468102");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41732");

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
    {'equal':'731', 'fixed_display':'SAPKB73135'},
    {'equal':'754', 'fixed_display':'SAPK-75416INSAPUI'},
    {'equal':'755', 'fixed_display':'SAPK-75513INSAPUI'},
    {'equal':'756', 'fixed_display':'SAPK-75610INSAPUI'},
    {'equal':'757', 'fixed_display':'SAPK-75707INSAPUI'},
    {'equal':'758', 'fixed_display':'SAPK-75802INSAPUI'},
    {'equal':'912', 'fixed_display':'SAPK-91201INSAPBASIS'}
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  abap:TRUE
);
