#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214580);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/07");

  script_cve_id(
    "CVE-2023-7272",
    "CVE-2024-23635",
    "CVE-2024-29857",
    "CVE-2024-30171",
    "CVE-2024-30172",
    "CVE-2024-34447",
    "CVE-2024-47554",
    "CVE-2025-21535",
    "CVE-2025-21549"
  );
  script_xref(name:"IAVA", value:"2025-A-0047");

  script_name(english:"Oracle WebLogic Server (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0, 14.1.1.0.0, and 14.1.2.0.0 versions of WebLogic Server installed on the remote host are affected by
multiple vulnerabilities as referenced in the January 2025 CPU advisory.

  - Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise
    Oracle WebLogic Server.  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic
    Server. (CVE-2024-23635)

  - Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle
    WebLogic Server.  While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional
    products (scope change). Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of Oracle WebLogic Server. (CVE-2023-7272)

  - Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle
    WebLogic Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle WebLogic Server. (CVE-2024-47554)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21535");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-23635");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_weblogic::get_app_info();

var constraints = [
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.250107', 'fixed_display' : '37453807' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.250108', 'fixed_display' : '37458537' },
  { 'min_version' : '14.1.2.0.0', 'fixed_version' : '14.1.2.0.250102', 'fixed_display' : '37439198' }
];

vcf::oracle_weblogic::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
