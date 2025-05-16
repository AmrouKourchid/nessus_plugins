#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185958);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/22");

  script_cve_id("CVE-2023-36049", "CVE-2023-36558");
  script_xref(name:"MSKB", value:"5032883");
  script_xref(name:"MSKB", value:"5032884");

  script_name(english:"Security Update for .NET Core SDK (November 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple Microsoft .NET Core SDK vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft .NET Core SDK installed on the remote host is 6.0.x prior to 6.0.125, 6.0.x prior to 
6.0.320, 6.0.x prior to 6.0.417, 7.0.x prior to 7.0.114, 7.0.x prior to 7.0.311, 7.0.x prior to 7.0.404, or 
8.0.x to 8.0.100. It is, therefore, affected by multiple vulnerabilities, as follows:

  - An elevation of privilege vulnerability exists in .NET where untrusted URIs provided to 
  System.Net.WebRequest.Create can be used to inject arbitrary commands to backend FTP servers.
  (CVE-2023-36049)
  
  - A security feature bypass vulnerability exists in ASP.NET where an unauthenticated user is able to bypass
  validation on Blazor server forms which could trigger unintended actions.(CVE-2023-36558)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/8.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36049");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36558");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.25/6.0.25.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aac42578");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.14/7.0.14.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cacbbd5");
  # https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.0/8.0.0.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e233323");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core SDK, remove vulnerable packages and refer to 5032883 and 5032884.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = '.NET Core SDK Windows';

var conversions = {"preview": -60};
vcf::add_conversions(conversions);
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '6.0', 'fixed_version': '6.0.125'},
  {'min_version': '6.0.200', 'fixed_version': '6.0.320'},
  {'min_version': '6.0.400', 'fixed_version': '6.0.417'},
  {'min_version': '7.0', 'fixed_version': '7.0.114'},
  {'min_version': '7.0.200', 'fixed_version': '7.0.311'},
  {'min_version': '7.0.400', 'fixed_version': '7.0.404'},
  {'min_version': '8.0.100-rc2', 'fixed_version': '8.0.100'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
