#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181277);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/12");

  script_cve_id(
    "CVE-2023-36792",
    "CVE-2023-36793",
    "CVE-2023-36794",
    "CVE-2023-36796"
  );
  script_xref(name:"IAVA", value:"2023-A-0475-S");

  script_name(english:"Security Update for Microsoft .NET Core (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2023_Sep_12 advisory.

  - Visual Studio Remote Code Execution Vulnerability (CVE-2023-36792, CVE-2023-36793, CVE-2023-36794,
    CVE-2023-36796)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/7.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36792");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36793");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36794");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36796");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5030559");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5030560");
  # https://github.com/dotnet/core/blob/master/release-notes/6.0.0/6.0.22/6.0.22.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f56a7a48");
  # https://github.com/dotnet/core/blob/master/release-notes/7.0.0/7.0.11/7.0.11.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bff6552");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36796");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'.NET Core Windows', win_local:TRUE);
var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.22' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.11' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
