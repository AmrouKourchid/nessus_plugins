#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211734);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id("CVE-2024-45663");
  script_xref(name:"IAVB", value:"2024-B-0183");

  script_name(english:"IBM DB2 DoS (7175943) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, IBM Db2 on Unix is vulnerable to a denial of service when querying 
certain tables using a specially crafted statement.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7175943");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_installed.nbin");
  script_require_keys("installed_sw/DB2 Server");
  script_exclude_keys("SMB/db2/Installed");

  exit(0);
}

include('vcf_extras_db2.inc');

# The remote host's OS is Windows, not Linux.
if (get_kb_item('SMB/db2/Installed'))
  audit(AUDIT_OS_NOT, 'Unix', 'Windows');

var app_info = vcf::ibm_db2::get_app_info();
# DB2 has an optional OpenSSH server that will run on
# windows.  We need to exit out if we picked up the windows
# installation that way.
if ('Windows' >< app_info['platform'])
  audit(AUDIT_HOST_NOT, 'a Unix based operating system');

var constraints = [
  {'min_version':'11.1', 'fixed_version':'11.1.4.0', 'fixed_display':'11.1.4.0 + Special Build 41535'},
  {'equal':'11.1.4.0', 'fixed_build':'41535'},
  {'min_version':'11.5', 'fixed_version':'11.5.8.0', 'fixed_display':'11.5.8.0 + Special Build 49307'},
  {'equal':'11.5.8.0', 'fixed_build':'49307'},
  {'equal':'11.5.9.0', 'fixed_build':'50315'},
  {'equal':'12.1.0.0', 'fixed_build':'50594'}
];
vcf::ibm_db2::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
