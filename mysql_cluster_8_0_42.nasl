#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234562);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2025-21574",
    "CVE-2025-21575",
    "CVE-2025-30681",
    "CVE-2025-30693",
    "CVE-2025-30710",
    "CVE-2025-30722"
  );
  script_xref(name:"IAVA", value:"2025-A-0272");

  script_name(english:"Oracle MySQL Cluster 8.0.x < 8.0.42 (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Cluster installed on the remote host are affected by multiple vulnerabilities as referenced in the
April 2025 CPU advisory.

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported versions
    that are affected are 7.6.0-7.6.33, 8.0.0-8.0.41, 8.4.0-8.4.4 and 9.0.0-9.2.0. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Cluster.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Cluster. (CVE-2025-21574)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported versions
    that are affected are 7.6.0-7.6.33, 8.0.0-8.0.41, 8.4.0-8.4.4 and 9.0.0-9.2.0. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Cluster.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Cluster. (CVE-2025-21575)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported versions
    that are affected are 7.6.0-7.6.33, 8.0.0-8.0.41, 8.4.0-8.4.4 and 9.0.0-9.2.0. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Cluster.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Cluster as well as unauthorized update, insert or delete access to some of
    MySQL Cluster accessible data. (CVE-2025-30693)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21574");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_cluster");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant:'Cluster', fixed:'8.0.42', min:'8.0', severity:SECURITY_WARNING);