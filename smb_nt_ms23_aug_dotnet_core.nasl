#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179502);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/01");

  script_cve_id(
    "CVE-2023-35390",
    "CVE-2023-35391",
    "CVE-2023-38178",
    "CVE-2023-38180"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/30");
  script_xref(name:"IAVA", value:"2023-A-0404-S");

  script_name(english:"Security Update for Microsoft .NET Core (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2023_Aug_08 advisory.

  - .NET and Visual Studio Remote Code Execution Vulnerability (CVE-2023-35390)

  - ASP.NET Core SignalR and Visual Studio Information Disclosure Vulnerability (CVE-2023-35391)

  - .NET Core and Visual Studio Denial of Service Vulnerability (CVE-2023-38178)

  - .NET and Visual Studio Denial of Service Vulnerability (CVE-2023-38180)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35390");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35391");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38178");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38180");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5029688");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5029689");
  # https://github.com/dotnet/core/blob/master/release-notes/6.0.0/6.0.21/6.0.21.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db3e4b01");
  # https://github.com/dotnet/core/blob/master/release-notes/7.0.0/7.0.10/7.0.10.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed757a70");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35391");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'.NET Core Windows', win_local:TRUE);
var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.21' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
