#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210867);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-43498", "CVE-2024-43499");
  script_xref(name:"IAVA", value:"2024-A-0734-S");
  script_xref(name:"IAVA", value:"2024-A-0726-S");

  script_name(english:"Security Update for Microsoft .NET Core SDK (November 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a Microsoft .NET Core SDK vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of .NET Core SDK installed on the remote host is 9.x prior to 9.0.0. 
It is, therefore, affected by denial of service vulnerability as referenced in the October 2024 advisory:

  - .NET Remote Code Execution (CVE-2024-43498)

  - .NET Denial of Service Vulnerability (CVE-2024-43499)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/9.0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-43498");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-43499");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/333");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/334");
  # https://github.com/dotnet/core/blob/main/release-notes/9.0/9.0.0/9.0.0.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c209efad");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = '.NET Core SDK Windows';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '9.0.0', 'fixed_version': '9.0.100'}
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
