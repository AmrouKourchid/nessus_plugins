#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208286);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2024-38229",
    "CVE-2024-43483",
    "CVE-2024-43484",
    "CVE-2024-43485"
  );
  script_xref(name:"IAVA", value:"2024-A-0625-S");
  script_xref(name:"IAVA", value:"2024-A-0632-S");

  script_name(english:"Security Update for Microsoft .NET Core (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the vendor advisory.

  - .NET and Visual Studio Remote Code Execution Vulnerability (CVE-2024-38229)

  - .NET and Visual Studio Denial of Service Vulnerability 
    (CVE-2024-43483,CVE-2024-43484,CVE-2024-43485)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/8.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/9.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38229");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43483");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43484");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43485");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5045993");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5045998");
  # https://github.com/dotnet/core/blob/main/release-notes/9.0/preview/rc2/README.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cc66f2f");
  # https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.10/8.0.10.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c2759dc");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.35/6.0.35.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2fe88ca");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'.NET Core Windows', win_local:TRUE);

vcf::add_separator('-');
var constraints = [
  { 'min_version' : '9.0.0-rc', 'fixed_version' : '9.0.0-rc.2.24474.3' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.10' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.35' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
