#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178229);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id("CVE-2023-29298", "CVE-2023-29300", "CVE-2023-29301");
  script_xref(name:"IAVA", value:"2023-A-0352-S");
  script_xref(name:"IAVA", value:"2023-A-0355-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/01/29");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/10");

  script_name(english:"Adobe ColdFusion < 2018.x < 2018u17 / 2021.x < 2021u7 / 2023.x < 2023u1 Multiple Vulnerabilities (APSB23-40)");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion installed on the remote Windows host is prior to 2018.x update 17, 2021.x update 7, or
2023.x update 1. It is, therefore, affected by multiple vulnerabilities as referenced in the APSB23-40 advisory.

  - Improper Access Control (CWE-284) potentially leading to Security feature bypass (CVE-2023-29298)

  - Deserialization of Untrusted Data (CWE-502) potentially leading to Arbitrary code execution
    (CVE-2023-29300)

  - Improper Restriction of Excessive Authentication Attempts (CWE-307) potentially leading to Security
    feature bypass (CVE-2023-29301)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb23-40.html");
  script_set_attribute(attribute:"solution", value:
"Update to Adobe ColdFusion version 2018 update 17 / 2021 update 7 / 2023 update 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29300");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(284, 307, 502);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  if (ver == '2018.0.0')
  {
    info = check_jar_chf(name, 17);
  }
  else if (ver == '2021.0.0')
  {
    info = check_jar_chf(name, 7);
  }
  else if (ver == '2023.0.0')
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

