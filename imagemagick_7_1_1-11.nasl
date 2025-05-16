#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179674);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2023-3195");
  script_xref(name:"IAVB", value:"2023-B-0038-S");

  script_name(english:"ImageMagick < 6.9.12-93 / 7.1.1.0 < 7.1.1-15 Buffer Overflow Condition");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by a buffer overflow condition");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is prior to 6.9.12-26 or 7.1.1-0 before 7.1.1-11. 
It is, therefore, affected by a buffer overflow condition in ImageMagick's coders/tiff.c. This flaw allows an attacker 
to trick the user into opening a specially crafted malicious tiff file, causing an application to crash, resulting in 
a denial of service.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-4f76-c3p6-5cgx");
  # https://github.com/ImageMagick/ImageMagick/commit/f620340935777b28fa3f7b0ed7ed6bd86946934c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52f050e8");
  # https://github.com/ImageMagick/ImageMagick6/commit/85a370c79afeb45a97842b0959366af5236e9023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c29915dd");
  # https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/V2ZUHZXQ2C3JZYKPW4XHCMVVL467MA2V/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa1caf89");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an unaffected version of ImageMagick.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

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

var app_info = vcf::combined_get_app_info(app:'ImageMagick');

var constraints = [
  {'fixed_version' : '6.9.12.93', 'fixed_display' : 'See vendor advisory'},
  {'min_version' : '7.1.1.0', 'fixed_version' : '7.1.1.15', 'fixed_display' : 'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
