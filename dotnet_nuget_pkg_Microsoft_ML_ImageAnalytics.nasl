#%NASL_MIN_LEVEL 80900

# (C) Tenable, Inc.

include('compat.inc');

if (description)
{
  script_id(208177);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_name(english:"NuGet Package 'Microsoft.ML.ImageAnalytics' Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Verified NuGet package status and is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has a 'Microsoft.ML.ImageAnalytics' with a Verified NuGet package status and is installed on the remote host.

Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nuget.org/packages/Microsoft.ML.ImageAnalytics/");
  script_set_attribute(attribute:"solution", value:
"The Microsoft.ML.ImageAnalytics package is installed on the remote host.");
  script_set_attribute(attribute:"agent", value:"all");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:microsoft.ml.imageanalytics");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nuget_package_enumeration_win_installed.nbin", "nuget_package_enumeration_nix_installed.nbin");

  exit(0);
}

include('vcf_extras_nuget.inc');

var app_info = vcf::nuget_package::get_app_info(pkg_name:"Microsoft.ML.ImageAnalytics");
app_info.vendor = "Microsoft";
app_info.cpe = "cpe:/a:microsoft:microsoft.ml.imageanalytics";
vcf::nuget_package::reg_install(app_info:app_info);
