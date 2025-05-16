#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(182199);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");
  script_xref(name:"IAVB", value:"2023-B-0072-S");

  script_name(english:"ImageMagick < 7.1.1-18 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is prior to 7.1.1-18  It is, therefore,
affected by a denial of service vulnerability.");
  # https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=60021&q=imagemagick&can=2&sort=-reported
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fbd0dc4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.1.1-18 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:"ImageMagick");

var constraints = [ {'fixed_version' : '7.1.1.18', 'fixed_display' : '7.1.1-18'} ];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
