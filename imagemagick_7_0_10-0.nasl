#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180509);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2023-3745");
  script_xref(name:"IAVB", value:"2023-B-0065-S");

  script_name(english:"ImageMagick 6.0 < 6.9.11-0, 7.0 < 7.0.10-0 Heap-based Buffer Overflow DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by heap-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is 6.0 prior to 6.9.11=0 or 7.0 prior to 
7.0.10-0. It is, therefore, affected by heap-based buffer overflow vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-3745");
  # https://github.com/ImageMagick/ImageMagick/issues/1857
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c2392e6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an unaffected version of ImageMagick.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3745");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/05");

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
  {'min_version':'6.0', 'fixed_version' : '6.9.11.0', 'fixed_display' : 'See vendor advisory'},
  {'min_version':'7.0', 'fixed_version' : '7.0.10.0', 'fixed_display' : 'See vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
