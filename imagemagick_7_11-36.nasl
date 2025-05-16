#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204966);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_cve_id("CVE-2024-41817");
  script_xref(name:"IAVB", value:"2023-B-0103");
  script_xref(name:"IAVB", value:"2024-B-0143-S");

  script_name(english:"ImageMagick < 7.1.1-36 Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is prior to 7.1.1-36. It is, therefore, affected 
by an arbitrary code execution vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed9d2119");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.1.1-36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41817");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'ImageMagick');

var constraints = [
  {'fixed_version' : '7.1.1.36', 'fixed_display' : '7.1.1-36'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
