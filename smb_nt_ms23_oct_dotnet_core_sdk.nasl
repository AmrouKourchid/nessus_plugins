#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182917);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/23");

  script_cve_id("CVE-2023-36435", "CVE-2023-38171", "CVE-2023-44487");
  script_xref(name:"MSKB", value:"5031900");
  script_xref(name:"MSKB", value:"5031901");
  script_xref(name:"MSFT", value:"MS23-5031900");
  script_xref(name:"MSFT", value:"MS23-5031901");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"IAVA", value:"2023-A-0543-S");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2023-B-0083-S");

  script_name(english:"Security Update for .NET Core SDK (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple Microsoft .NET Core SDK vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft .NET Core SDK installed on the remote host is 6.0.x prior to 6.0.123, 6.0.x prior to 
6.0.318, 6.0.x prior to 6.0.414, 7.0.x prior to 7.0.112 or 7.0.x prior to 7.0.309 or 7.0.x prior to 7.0.402.
It is, therefore, affected by multiple vulnerabilities, as follows:

  - A vulnerability exists in the ASP.NET Core Kestrel web server where a malicious client may flood the 
  server with specially crafted HTTP/2 requests, causing denial of service. (CVE-2023-44487)
  
  - A null pointer vulnerability exists in MsQuic.dll which may lead to Denial of Service. This issue only 
  affects Windows systems. (CVE-2023-38171)

  - A memory leak vulnerability exists in MsQuic.dll which may lead to Denial of Service. This issue only
  affects Windows systems. (CVE-2023-36435)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36435");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38171");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-44487");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.22/6.0.23.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327d233f");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.11/7.0.12.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b24a5373");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core SDK, remove vulnerable packages and refer to 5031900 and 5031901.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = '.NET Core SDK Windows';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '6.0', 'fixed_version': '6.0.123'},
  {'min_version': '6.0.200', 'fixed_version': '6.0.318'},
  {'min_version': '6.0.400', 'fixed_version': '6.0.415'},
  {'min_version': '7.0', 'fixed_version': '7.0.112'},
  {'min_version': '7.0.200', 'fixed_version': '7.0.309'},
  {'min_version': '7.0.400', 'fixed_version': '7.0.402'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
