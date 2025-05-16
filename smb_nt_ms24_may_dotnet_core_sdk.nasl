#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197080);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/16");

  script_cve_id("CVE-2024-30045");
  script_xref(name:"MSKB", value:"5038351");
  script_xref(name:"MSKB", value:"5038352");

  script_name(english:"Security Update for Microsoft .NET Core SDK (May 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a Microsoft .NET Core SDK vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of .NET Core SDK installed on the remote host is 7.x prior to 7.0.19 or 8.x prior to 8.0.5. 
It is, therefore, affected by remote code execution vulnerability as referenced in the May 2024 advisory:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-30045)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/8.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-30045");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.19/7.0.19.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8236545d");
  # https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.5/8.0.5.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9307ff5");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = '.NET Core SDK Windows';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '7.0', 'fixed_version': '7.0.119'},
  {'min_version': '7.0.200', 'fixed_version': '7.0.316'},
  {'min_version': '7.0.400', 'fixed_version': '7.0.409'},
  {'min_version': '8.0', 'fixed_version': '8.0.105'},
  {'min_version': '8.0.200-rc', 'fixed_version': '8.0.205', 'fixed_display': '8.0.205 / 8.0.300'}
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
