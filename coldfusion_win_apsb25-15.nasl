#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234235);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2025-24446",
    "CVE-2025-24447",
    "CVE-2025-30281",
    "CVE-2025-30282",
    "CVE-2025-30284",
    "CVE-2025-30285",
    "CVE-2025-30286",
    "CVE-2025-30287",
    "CVE-2025-30288",
    "CVE-2025-30289",
    "CVE-2025-30290",
    "CVE-2025-30291",
    "CVE-2025-30292",
    "CVE-2025-30293",
    "CVE-2025-30294"
  );
  script_xref(name:"IAVA", value:"2025-A-0231");

  script_name(english:"Adobe ColdFusion 2021.x < 2021u19 / 2023.x < 2023u13 / 2025.x < 2025u1 Multiple Vulnerabilities (APSB25-15)");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host is prior to 2021.x update 19, 2023.x update 13, or
2025.x update 1. It is, therefore, affected by multiple vulnerabilities as referenced in the APSB25-15 advisory.

  - Improper Authentication (CWE-287) potentially leading to Arbitrary code execution (CVE-2025-30282,
    CVE-2025-30287)

  - Deserialization of Untrusted Data (CWE-502) potentially leading to Arbitrary code execution
    (CVE-2025-24447, CVE-2025-30284, CVE-2025-30285)

  - Improper Input Validation (CWE-20) potentially leading to Arbitrary file system read (CVE-2025-24446)

  - Improper Access Control (CWE-284) potentially leading to Arbitrary file system read (CVE-2025-30281)

  - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') (CWE-78)
    potentially leading to Arbitrary code execution (CVE-2025-30286, CVE-2025-30289)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb25-15.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 2021 update 19 / 2023 update 13 / 2025 update 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");  
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24447");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-30282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 200, 22, 284, 287, 502, 78, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}


include('coldfusion_win.inc');

var instances = get_coldfusion_instances();
var instance_info = [];

foreach var name (keys(instances))
{
  var info = NULL;
  var ver = instances[name];

  if (ver =~ "^2021($|\.)")
  {
    info = check_jar_chf(name, 19);
  }
  else if (ver =~ "^2023($|\.)")
  {
    info = check_jar_chf(name, 13);
  }
  else if (ver =~ "^2025($|\.)")
  {
    info = check_jar_chf(name, 1);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Adobe ColdFusion');

var port = get_kb_item('SMB/transport');
if (!port)
  port = 445;

  var report =
  '\n' + 'Nessus detected the following unpatched instances :' +
  '\n' + join(instance_info, sep:'\n') +
  '\n' + 'Also note that to be fully protected the Java JDK must be patched along with applying the vendor patch.';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);

