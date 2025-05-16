#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214311);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-12744");
  script_xref(name:"IAVA", value:"2025-A-0011");

  script_name(english:"RedShift JDBC Driver < 2.1.0.32 (CVE-2024-12744)");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Amazon Redshift JDBC Driver, version 2.1.0.31, is affected by CVE-2024-12744, a SQL injection issue when 
utilizing the get_schemas, get_tables, or get_columns Metadata APIs. This issue has been addressed in driver 
version 2.1.0.32. We recommend customers upgrade to the driver version 2.1.0.32 or revert to driver version 2.1.0.30.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-655w-fm8m-m478");
  script_set_attribute(attribute:"solution", value:
"Upgrade Redshift JDBC Driver version >= 2.1.0.32 or revert to 2.1.0.30 or less.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-12744");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:aws:redshift_jdbc_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redshift_jdbc_installed.nbin");
  script_require_ports("Host/detect/db/JAR");

  exit(0);
}

include('vcf.inc');

var app_name = 'RedShift JDBC Driver';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'equal': '2.1.0.31' , 'fixed_display': 'Revert to 2.1.0.30 or prior, or upgrade to 2.1.0.32 or later' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
