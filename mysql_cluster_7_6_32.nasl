#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209240);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2024-5535",
    "CVE-2024-21203",
    "CVE-2024-21218",
    "CVE-2024-21230",
    "CVE-2024-21238",
    "CVE-2024-21247"
  );
  script_xref(name:"IAVA", value:"2024-A-0658");

  script_name(english:"Oracle MySQL Cluster 7.5.x < 7.5.36 / 7.6.x < 7.6.32 (October 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Cluster installed on the remote host are affected by multiple vulnerabilities as referenced in the
October 2024 CPU advisory.

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: Packaging (OpenSSL)). 
    Supported versions that are affected are 7.5.35 and prior, 7.6.31 and prior, 8.0.39 and prior, 8.4.2 and 
    prior and 9.0.1 and prior. Easily exploitable vulnerability allows unauthenticated attacker with network 
    access via multiple protocols to compromise MySQL Cluster. Successful attacks of this vulnerability can 
    result in unauthorized access to critical data or complete access to all MySQL Cluster accessible data 
    and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Cluster.
    (CVE-2024-5535)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported 
    versions that are affected are 7.5.35 and prior, 7.6.31 and prior, 8.0.39 and prior, 8.4.2 and prior 
    and 9.0.1 and prior. Difficult to exploit vulnerability allows low privileged attacker with network 
    access via multiple protocols to compromise MySQL Cluster. Successful attacks of this vulnerability 
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of 
    MySQL Cluster. (CVE-2024-21238)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported 
    versions that are affected are 7.5.35 and prior, 7.6.31 and prior, 8.0.39 and prior, 8.4.2 and prior and 
    9.0.1 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via 
    multiple protocols to compromise MySQL Cluster. Successful attacks of this vulnerability can result in 
    unauthorized update, insert or delete access to some of MySQL Cluster accessible data as well as 
    unauthorized read access to a subset of MySQL Cluster accessible data. (CVE-2024-21247)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21203");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-21238");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_cluster");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

#combining multiple fix, min version will automatically the base of the fix version, like 8.0.x, 8.4.x 9.0.x 
mysql_check_version(fixed:make_list('7.5.36', '7.6.32'), variant:'Cluster', severity:SECURITY_WARNING);
