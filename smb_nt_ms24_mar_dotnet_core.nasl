#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192012);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/11");

  script_cve_id("CVE-2024-21392");
  script_xref(name:"IAVA", value:"2024-A-0151-S");

  script_name(english:"Security Update for Microsoft .NET Core (March 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 2024_Mar_12 advisory.

  - .NET and Visual Studio Denial of Service Vulnerability (CVE-2024-21392)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/8.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21392");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5036451");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5036452");
  # https://github.com/dotnet/core/blob/master/release-notes/7.0.0/7.0.17/7.0.17.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e42444df");
  # https://github.com/dotnet/core/blob/master/release-notes/8.0.0/8.0.3/8.0.3.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad07e239");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'.NET Core Windows', win_local:TRUE);
var constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.17' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.3' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
