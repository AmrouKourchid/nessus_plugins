#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209248);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2021-37519",
    "CVE-2024-21193",
    "CVE-2024-21194",
    "CVE-2024-21196",
    "CVE-2024-21197",
    "CVE-2024-21198",
    "CVE-2024-21199",
    "CVE-2024-21201",
    "CVE-2024-21203",
    "CVE-2024-21209",
    "CVE-2024-21213",
    "CVE-2024-21218",
    "CVE-2024-21219",
    "CVE-2024-21230",
    "CVE-2024-21231",
    "CVE-2024-21232",
    "CVE-2024-21236",
    "CVE-2024-21237",
    "CVE-2024-21238",
    "CVE-2024-21239",
    "CVE-2024-21241",
    "CVE-2024-21243",
    "CVE-2024-21244",
    "CVE-2024-21247",
    "CVE-2024-7264",
    "CVE-2024-5535",
    "CVE-2024-37371",
    "CVE-2025-21494",
    "CVE-2025-21504",
    "CVE-2025-21521",
    "CVE-2025-21525",
    "CVE-2025-21534",
    "CVE-2025-21536"
  );
  script_xref(name:"IAVA", value:"2025-A-0050");

  script_name(english:"Oracle MySQL Server 8.x < 8.4.3 (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Server installed on the remote host are affected by a vulnerability as referenced in the
January 2024 CPU advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (Kerberos)). Supported
    versions that are affected are 8.0.39 and prior, 8.4.2 and prior and  9.0.1 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server.  Successful
    attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all MySQL
    Server accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
    Server. (CVE-2024-37371)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (OpenSSL)).
    Supported versions that are affected are 8.0.39 and prior, 8.4.2 and prior and 9.0.1 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL
    Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all MySQL Server accessible data and unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2024-5535)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (curl)). Supported
    versions that are affected are 8.0.39 and prior, 8.4.2 and prior and 9.0.1 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server. (CVE-2024-7264)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2024.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37371");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mysql_version_local.nasl", "mysql_win_installed.nbin", "macosx_mysql_installed.nbin");
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}

include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '8.1', 'fixed_version' : '8.4.3'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
