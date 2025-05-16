#%NASL_MIN_LEVEL 80900
##
# Tenable, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(185581);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2023-36018");

  script_name(english:"Security Update for Microsoft Visual Studio Code (November 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A Jupyter extension spoofing vulnerability exists in Visual Studio Code when the installed Jupyter 
extension is prior to 2023.10.1100000000.

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  # https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2023-36018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1dc9962");
  # https://marketplace.visualstudio.com/items/ms-toolsai.jupyter/changelog
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ce2668f");
  # https://marketplace.visualstudio.com/items?itemName=ms-toolsai.jupyter
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e489da8");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jupyter extension of VS Code to 2023.10.1100000000 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_code_win_extensions_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio Code");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'vs-code::jupyter', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '2023.10.1100000000' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
