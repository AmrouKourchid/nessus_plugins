#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181406);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id(
    "CVE-2023-36792",
    "CVE-2023-36793",
    "CVE-2023-36794",
    "CVE-2023-36796",
    "CVE-2023-36799"
  );
  script_xref(name:"MSKB", value:"5030559");
  script_xref(name:"MSKB", value:"5030560");
  script_xref(name:"MSFT", value:"MS23-5030559");
  script_xref(name:"MSFT", value:"MS23-5030560");
  script_xref(name:"IAVA", value:"2023-A-0475-S");

  script_name(english:"Security Update for .NET Core SDK (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple Microsoft .NET Core SDK vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft .NET Core SDK installed on the remote host is 6.0.x prior to 6.0.122, 6.0.x prior to 
6.0.317, 6.0.x prior to 6.0.414, 7.0.x prior to 7.0.111 or 7.0.x prior to 7.0.308 or 7.0.x prior to 7.0.401.
It is, therefore, affected by multiple vulnerabilities, as follows:

  - A vulnerability exists in Microsoft.DiaSymReader.Native.amd64.dll when reading a corrupted PDB file which
  may lead to remote code execution. This issue only affects Windows systems. (CVE-2023-36792)
  
  - A vulnerability exists in Microsoft.DiaSymReader.Native.amd64.dll when reading a corrupted PDB file which
  may lead to remote code execution. This issue only affects Windows systems. (CVE-2023-36793)

  - A vulnerability exists in Microsoft.DiaSymReader.Native.amd64.dll when reading a corrupted PDB file which
  may lead to remote code execution. This issue only affects Windows systems. (CVE-2023-36794)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36792");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36793");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36794");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.22/6.0.22.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4487bb99");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.11/7.0.11.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20ca84fb");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core SDK, remove vulnerable packages and refer to KB5030559 and KB5030560.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36796");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '6.0', 'fixed_version': '6.0.122'},
  {'min_version': '6.0.200', 'fixed_version': '6.0.317'},
  {'min_version': '6.0.400', 'fixed_version': '6.0.414'},
  {'min_version': '7.0', 'fixed_version': '7.0.111'},
  {'min_version': '7.0.200', 'fixed_version': '7.0.308'},
  {'min_version': '7.0.400', 'fixed_version': '7.0.401'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
