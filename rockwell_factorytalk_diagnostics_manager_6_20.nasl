#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187748);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/10");

  script_cve_id("CVE-2020-6967");
  script_xref(name:"ICSA", value:"20-051-02");

  script_name(english:"Rockwell FactoryTalk Services Platform < 6.20 Deserialization");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rockwell FactoryTalk Services Platform installed on the remote Windows host is prior to 6.20. It is, therefore, affected by a
vulnerability.

  - Factory Talk Diagnostics exposes a .NET Remoting endpoint via
    RNADiagnosticsSrv.exe at TCP/8082, which can insecurely deserialize
    untrusted data. (CVE-2020-6967)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-20-051-02-0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rockwell FactoryTalk Services Platform version 6.20 or later or refer to the vendor advisory for other mitigations.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6967");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rockwellautomation:factorytalk_services_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rockwell_factorytalk_services_platform_win_installed.nbin");
  script_require_keys("installed_sw/Rockwell FactoryTalk Services Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('installed_sw/Rockwell FactoryTalk Services Platform');

var app_info = vcf::get_app_info(app:'Rockwell FactoryTalk Services Platform', win_local:TRUE);

if (!empty_or_null(app_info['RNADiagnosticsSrv.exe']))
  app_info.version = app_info['RNADiagnosticsSrv.exe'];

var constraints = [
  { 'min_version' : '2.00', 'fixed_version' : '6.20', 'fixed_display' : 'See vendor advisory.' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
