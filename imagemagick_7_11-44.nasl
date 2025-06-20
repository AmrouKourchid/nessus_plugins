#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235110);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/03");

  script_cve_id("CVE-2025-46393");
  script_xref(name:"IAVB", value:"2025-B-0062");

  script_name(english:"ImageMagick < 7.1.1-44 Incorrect Calculation of Buffer Size");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by an incorrect calculation of buffer size vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is prior to 7.1.1-44. It is, therefore, affected 
by an incorrect calculation of buffer size vulnerability..

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/ImageMagick/Website/blob/main/ChangeLog.md#711-44---2025-02-22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?432cfac1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.1.1-44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-46393");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute: "thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl", "imagemagick_macos_installed.nbin");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match_one': {'os': ['windows', 'macos']}}
  ],
  'checks': [
    {
      'check_algorithm': 'default',
      'product': {'name': 'ImageMagick', 'type': 'app'},
      'constraints': [
        {
          'fixed_version' : '7.1.1.44', 'fixed_display': '7.1.1-44'
        }
      ] 
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);
