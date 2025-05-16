#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235819);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2025-0915", "CVE-2025-1000");
  script_xref(name:"IAVB", value:"2025-B-0068");

  script_name(english:"IBM DB2 Multiple Vulnerabilities (7232529, 7232528) (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, IBM Db2 on Windows may be affected by multiple vulnerabilites:

  - IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server) under specific configurations could 
    allow an authenticated user to cause a denial of service due to insufficient release of allocated memory 
    resources. (CVE-2025-0915)

  - IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server) could allow an authenticated user to 
    cause a denial of service when connecting to a z/OS database due to improper handling of automatic client 
    rerouting. (CVE-2025-1000)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7232529");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7232528");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0915");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2/Installed");

  exit(0);
}

include('vcf_extras_db2.inc');

get_kb_item_or_exit('SMB/db2/Installed');
var app_info = vcf::ibm_db2::get_app_info();

var constraints = [
  {'min_version':'11.5.9000', 'fixed_version':'11.5.9000.352', 'fixed_display':'11.5.9000.352 Special Build 55285'},
  {'min_version':'12.1.1000', 'fixed_version':'12.1.1000.77', 'fixed_display':'12.1.1000.77 Special Build 54779'}
];
vcf::ibm_db2::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
