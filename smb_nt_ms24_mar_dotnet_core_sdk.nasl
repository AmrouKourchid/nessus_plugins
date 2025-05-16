#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192026);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id("CVE-2024-21392", "CVE-2024-26190");
  script_xref(name:"MSKB", value:"5036451");
  script_xref(name:"MSKB", value:"5036452");
  script_xref(name:"IAVA", value:"2024-A-0151-S");

  script_name(english:"Security Update for Microsoft .NET Core SDK (March 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple Microsoft .NET Core SDK vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of .NET Core SDK installed on the remote host is 6.x prior to 6.0.27, 7.x prior to 7.0.16 or 8.x prior to 
8.0.2. It is, therefore, affected by multiple vulnerabilities as referenced in the February 2024 advisory:

  - A vulnerability exists in .NET where specially crafted requests may cause a resource leak, leading to a 
    denial of service. (CVE-2024-21392)

  - A Vulnerability exist in MsQuic.dll which might result in a peer to allocate small chunks of memory as 
    long as connection stays alive. (CVE-2024-26190) 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/8.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21392");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-26190");
  # https://support.microsoft.com/en-gb/topic/-net-7-0-update-march-12-2024-kb5036451-2a609009-3dc8-4f7f-b8e3-7b67ee96f8cb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30bf8525");
  # https://support.microsoft.com/en-gb/topic/-net-8-0-update-march-12-2024-kb5036452-118a3a49-de91-4f65-b12f-f83d7b9dbf50
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?009a49ad");
  # https://devblogs.microsoft.com/dotnet/march-2024-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea9c12e4");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.17/7.0.17.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c1f6694");
  # https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.3/8.0.3.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31dd917c");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26190");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/13");

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
  {'min_version': '7.0', 'fixed_version': '7.0.117'},
  {'min_version': '7.0.200', 'fixed_version': '7.0.314'},
  {'min_version': '7.0.400', 'fixed_version': '7.0.407'},
  {'min_version': '8.0', 'fixed_version': '8.0.103'},
  {'min_version': '8.0.200-rc', 'fixed_version': '8.0.202'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
