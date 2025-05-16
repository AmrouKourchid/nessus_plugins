#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180502);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/01");

  script_cve_id("CVE-2023-35390", "CVE-2023-35391", "CVE-2023-38180");
  script_xref(name:"MSKB", value:"5029688");
  script_xref(name:"MSKB", value:"5029689");
  script_xref(name:"MSFT", value:"MS23-5029688");
  script_xref(name:"MSFT", value:"MS23-5029689");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/30");

  script_name(english:"Security Update for .NET Core SDK (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple Microsoft .NET Core SDK vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft .NET Core SDK installed on the remote host is 6.0.x prior to 6.0.121, 6.0.x prior to 
6.0.316, 6.0.x prior to 6.0.413, 7.0.x prior to 7.0.110 or 7.0.x prior to 307. It is, therefore, affected by 
multiple vulnerabilities, as follows:

  - A vulnerability exists when some dotnet commands are used in directories with weaker permissions which
  can result in remote code execution. (CVE-2023-35390)
  
  - A vulnerability exists in .NET 6.0 and .NET 7.0 applications using SignalR when redis backplane use might
  result in information disclosure. (CVE-2023-35391)

  - A vulnerability exists in Kestrel where, on detecting a potentially malicious client, Kestrel will 
  sometimes fail to disconnect it, resulting in denial of service. (CVE-2023-38180)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/sdk/security/advisories/GHSA-p8rx-fwgq-rh2f");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35390");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35391");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38180");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.21/6.0.21.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcaaf116");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.10/7.0.10.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7b7e1c7");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core SDK, remove vulnerable packages and refer to KB5029688 and KB5029689.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35391");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = '.NET Core SDK Windows';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '6.0', 'fixed_version': '6.0.121'},
  {'min_version': '6.0.200', 'fixed_version': '6.0.316'},
  {'min_version': '6.0.400', 'fixed_version': '6.0.413'},
  {'min_version': '7.0', 'fixed_version': '7.0.110'},
  {'min_version': '7.0.200', 'fixed_version': '7.0.307', 'fixed_display': '7.0.307 / 7.0.400'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
