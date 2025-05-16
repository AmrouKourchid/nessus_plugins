#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193576);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/06");

  script_cve_id(
    "CVE-2023-52425",
    "CVE-2024-0853",
    "CVE-2024-21101",
    "CVE-2024-21102"
  );
  script_xref(name:"IAVA", value:"2024-A-0240");

  script_name(english:"Oracle MySQL Cluster 8.0.x < 8.0.37 (Apr 2024 / Jul 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Cluster installed on the remote host are affected by multiple vulnerabilities as referenced in the
April / July 2024 CPU advisory.

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General (LibExpat)). 
    Supported versions that are affected are 8.0.36 and prior and 8.3.0 and prior. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise 
    MySQL Cluster. Successful attacks of this vulnerability can result in unauthorized ability to cause a 
    hang or frequently repeatable crash (complete DOS) of MySQL Cluster. July 2024 CPU (CVE-2023-52425)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported
    versions that are affected are 7.5.33 and prior, 7.6.29 and prior, 8.0.36 and prior and 8.3.0 and prior.
    Difficult to exploit vulnerability allows high privileged attacker with network access via multiple
    protocols to compromise MySQL Cluster. Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of MySQL Cluster accessible data. April CPU (CVE-2024-21101)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported
    versions that are affected are 7.5.33 and prior, 7.6.29 and prior, 8.0.36 and prior and 8.3.0 and prior.
    Easily exploitable vulnerability allows high privileged attacker with network access via multiple
    protocols to compromise MySQL Cluster. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Cluster.  April CPU
    (CVE-2024-21102)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April or July 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0853");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_cluster");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant:'Cluster', fixed:'8.0.37', min:'8.0', severity:SECURITY_WARNING);
