#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(178206);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/01");

  script_cve_id("CVE-2023-33127", "CVE-2023-33170");
  script_xref(name:"IAVA", value:"2023-A-0340-S");

  script_name(english:"Security Updates for Microsoft ASP.NET Core (July 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET core installations on the remote host are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities exist in ASP.NET Core 6.0 < 6.0.20 and ASP.NET Core 7.0 < 7.0.9.

  - A vulnerability exists in .NET applications where the diagnostic server can be exploited to achieve
  cross-session/cross-user elevation of privilege (EoP) and code execution. (CVE-2023-33127)

  - A vulnerability exists in ASP.NET Core applications where account lockout maximum failed attempts may not 
  be immediately updated, allowing an attacker to try more passwords. (CVE-2023-33170)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.20/6.0.20.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0c23ddd");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.9/7.0.9.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c11c7bc");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/7.0");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core Runtime to version 6.0.20 or 7.0.9");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33127");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");

  exit(0);
}

include('vcf.inc');

var app = 'ASP .NET Core Windows';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '6.0',  'fixed_version': '6.0.20'},
  {'min_version': '7.0',  'fixed_version': '7.0.9'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
