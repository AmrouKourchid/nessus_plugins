#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(182957);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/23");

  script_cve_id("CVE-2023-44487");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"IAVA", value:"2023-A-0545-S");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2023-B-0083-S");

  script_name(english:"Security Updates for Microsoft ASP.NET Core (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET core installations on the remote host are affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ASP.NET core installed on the remote host is affected by a denial of service (DoS) vulnerability. The
HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many
streams quickly, as exploited in the wild in August through October 2023.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.23/6.0.23.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28615a1b");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.12/7.0.12.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2176e0b");
  # https://github.com/dotnet/core/blob/main/release-notes/8.0/preview/8.0.0-rc.2.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da7ab951");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/8.0");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core Runtime to version 6.0.23, 7.0.12, 8.0.0-rc2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");

  exit(0);
}

include('vcf.inc');

var app = 'ASP .NET Core Windows';

var conversions = {"preview" : -60};
vcf::add_conversions(conversions);
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '6.0',  'fixed_version': '6.0.23'},
  {'min_version': '7.0',  'fixed_version': '7.0.12'},
  {'min_version': '8.0.0-alpha.0',  'fixed_version': '8.0.0-rc.2.23480.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
