#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197064);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2024-30054");
  script_xref(name:"IAVA", value:"2024-A-0286-S");

  script_name(english:"NuGet Package 'Microsoft.PowerBI.JavaScript' < 2.23.1 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a NuGet package installed that has an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of the NuGet Package 'Microsoft.PowerBI.JavaScript' that is prior to 2.23.1 It is,
therefore, affected by an information disclosure vulnerability. An unauthenticated, remote attacker can exploit this,
via user interaction, to disclose potentially sensitive information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30054");
  script_set_attribute(attribute:"see_also", value:"https://www.nuget.org/packages/Microsoft.PowerBI.JavaScript/");
  script_set_attribute(attribute:"solution", value:
"Update the 'Microsoft.PowerBI.JavaScript' package to version 2.23.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30054");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:nuget");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nuget_package_enumeration_win_installed.nbin", "nuget_package_enumeration_nix_installed.nbin");

  exit(0);
}

include('vcf_extras_nuget.inc');

var app_info = vcf::nuget_package::get_app_info(pkg_name:'Microsoft.PowerBI.JavaScript');

var constraints = [
  { 'fixed_version': '2.23.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
