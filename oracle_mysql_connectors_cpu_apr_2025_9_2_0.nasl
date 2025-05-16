#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234561);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2024-7254");
  script_xref(name:"IAVA", value:"2025-A-0272");

  script_name(english:"Oracle MySQL Connectors CVE-2024-7254 (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 9.0.0 and 9.2.0 versions of MySQL Connectors installed on the remote host is affected by CVE-2024-7254
as referenced in the April 2025 CPU advisory.

  - Any project that parses untrusted Protocol Buffers data containing an arbitrary number of nested groups / series of 
    SGROUP tags can corrupted by exceeding the stack limit i.e. StackOverflow. Parsing nested groups as unknown fields 
    with DiscardUnknownFieldsParser or Java Protobuf Lite parser, or against Protobuf map fields, creates unbounded 
    recursions that can be abused by an attacker.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7254");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin", "jar_detect_nix.nbin", "jar_detect_win.nbin");
  script_require_keys("installed_sw/MySQL Connector", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

var jar_table = get_kb_item_or_exit('Host/detect/db/JAR');

function protobuf_jar_detected(){
  var sql_like = "%protobuf-java%.jar";

  var result = query_scratchpad("SELECT filepath, versionInfo FROM "+jar_table+" WHERE filepath LIKE '" + sql_like + "';");

  return !empty_or_null(result);
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::get_app_info(app:'MySQL Connector');
var product = tolower(app_info['Product']);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('mysql connector j' == product && protobuf_jar_detected())
{
  var constraints = [{ 'min_version' : '9.0.0', 'fixed_version' : '9.2.0' }];

  vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

} 
else 
{
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);
}

