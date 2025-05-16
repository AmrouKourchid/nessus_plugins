#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198066);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id("CVE-2024-22476", "CVE-2024-21792");

  script_name(english:"Intel Neural Compressor < 2.5.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Intel Neural Compressor installed on the remote host is prior to 2.5.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the release notes.

    Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01109.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14205bfd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Intel Neural Compressor version 2.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:neural_compressor");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_neural_compressor_detect.nbin");
  script_require_keys("installed_sw/neural-compressor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'neural-compressor');
var constraints = [
    {'fixed_version':'2.5.0' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

