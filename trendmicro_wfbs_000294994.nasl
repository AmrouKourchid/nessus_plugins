#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192566);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/26");

  script_cve_id("CVE-2023-41179");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/12");

  script_name(english:"Trend Micro Worry-Free Business Security (WFBS) Command Execution Vulnerability (000294994)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by a command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Trend Micro WFBS which is affected by a command execution vulnerability 
in the 3rd party AV uninstaller module contained in Worry-Free Business Security which could allow an attacker to 
manipulate the module to execute arbitrary commands on an affected installation.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/dcx/s/solution/000294994");
  script_set_attribute(attribute:"solution", value:
"Apply patch build 2495 or later as advised in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41179");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_server_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Worry-Free Business Security Advanced");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Trend Micro Worry-Free Business Security Advanced');
vcf::check_granularity(app_info:app_info, sig_segments:4);

var constraints = [
  {'min_version':'20.0.0', 'fixed_version':'20.0.0.2495', 'fixed_display': '10.0 SP1 Patch 2495'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
