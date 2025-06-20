#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(168826);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/20");

  script_cve_id("CVE-2022-41089");
  script_xref(name:"MSKB", value:"5021953");
  script_xref(name:"MSKB", value:"5021954");
  script_xref(name:"MSKB", value:"5021955");
  script_xref(name:"MSFT", value:"MS22-5021953");
  script_xref(name:"MSFT", value:"MS22-5021954");
  script_xref(name:"MSFT", value:"MS22-5021955");
  script_xref(name:"IAVA", value:"2022-A-0526");

  script_name(english:"Security Updates for Microsoft ASP.NET Core (December 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET core installations on the remote host are affected by remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in ASP.NET core 3.1, ASP.NET 6.0, and ASP.NET 7.0, where a malicious 
actor could cause a user to run arbitrary code as a result of parsing maliciously crafted xps files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021953");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021954");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021955");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core Runtime to version 3.1.32 or 6.0.12 or 7.0.1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");

  exit(0);
}

include('vcf.inc');

var app = 'ASP .NET Core Windows';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '3.1', 'fixed_version': '3.1.32'},
  {'min_version': '6.0', 'fixed_version': '6.0.12'},
  {'min_version': '7.0', 'fixed_version': '7.0.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
