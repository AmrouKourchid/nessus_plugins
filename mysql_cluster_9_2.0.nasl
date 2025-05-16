#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214581);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/27");

  script_cve_id(
    "CVE-2025-21518",
    "CVE-2025-21520",
    "CVE-2025-21531",
    "CVE-2025-21543"
  );
  script_xref(name:"IAVA", value:"2025-A-0050");

  script_name(english:"Oracle MySQL Cluster 9.0.x < 9.2.0 (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Cluster installed on the remote host are affected by multiple vulnerabilities as referenced in the
January 2025 CPU advisory.

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported 
    versions that are affected are 7.6.32 and prior, 8.0.40 and prior, 8.4.3 and prior and 9.1.0 and prior. 
    Easily exploitable vulnerability allows low privileged attacker with network access via multiple 
    protocols to compromise MySQL Cluster. Successful attacks of this vulnerability can result in 
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Cluster. 
    (CVE-2025-21518)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported 
    versions that are affected are 7.6.32 and prior, 8.0.40 and prior, 8.4.3 and prior and 9.1.0 and prior. 
    Difficult to exploit vulnerability allows high privileged attacker with logon to the infrastructure 
    where MySQL Cluster executes to compromise MySQL Cluster. Successful attacks require human interaction 
    from a person other than the attacker. Successful attacks of this vulnerability can result in 
    unauthorized read access to a subset of MySQL Cluster accessible data. (CVE-2025-21520)

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported 
    versions that are affected are 7.6.32 and prior, 8.0.40 and prior, 8.4.3 and prior and 9.1.0 and prior. 
    Easily exploitable vulnerability allows high privileged attacker with network access via multiple 
    protocols to compromise MySQL Cluster. Successful attacks of this vulnerability can result in 
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Cluster. 
    (CVE-2025-21531)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21518");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-21520");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

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

# min is 9.0 base from the download page https://downloads.mysql.com/archives/cluster/
mysql_check_version(variant:'Cluster', fixed:'9.2.0', min:'9.0', severity:SECURITY_WARNING);