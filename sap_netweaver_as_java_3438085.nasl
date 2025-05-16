#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205612);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-33005");
  script_xref(name:"IAVA", value:"2024-A-0497");

  script_name(english:"SAP NetWeaver AS Java Missing Authorization (3438085)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SAP NetWeaver application server is affected by a missing authorization vulnerability.");
  script_set_attribute(attribute:"description", value:
"Due to the missing authorization checks in the local systems, the admin users of SAP Web Dispatcher, SAP NetWeaver
Application Server (ABAP and Java), and SAP Content Server can impersonate other users and may perform some
unintended actions. This could lead to a low impact on confidentiality and a high impact on the integrity and
availability of the applications.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3438085");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-33005");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::sap_netweaver_as::get_app_info(kernel:TRUE);

var constraints = [
    {'equal':'7.22', 'fixed_display':'See vendor advisory'},
    {'equal':'7.53', 'fixed_display':'See vendor advisory'},
    {'equal':'7.54', 'fixed_display':'See vendor advisory'},
    {'equal':'7.77', 'fixed_display':'See vendor advisory'},
    {'equal':'7.85', 'fixed_display':'See vendor advisory'},
    {'equal':'7.89', 'fixed_display':'See vendor advisory'},
    {'equal':'7.93', 'fixed_display':'See vendor advisory'}
];

vcf::sap_netweaver_as::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  kernel:TRUE
);