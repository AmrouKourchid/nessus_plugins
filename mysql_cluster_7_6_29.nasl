#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189353);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2024-20965");
  script_xref(name:"IAVA", value:"2024-A-0034-S");

  script_name(english:"Oracle MySQL Cluster 7.6.x < 7.6.29 (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by os command injection vulnerability");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Cluster installed on the remote host are affected by a vulnerability as referenced in the
January 2024 CPU advisory.

  - Vulnerability in the MySQL Cluster product of Oracle MySQL (component: Cluster: General). Supported 
    versions that are affected are 7.5.32 and prior, 7.6.28 and prior, 8.0.35 and prior and 8.2.0 and prior. 
    Easily exploitable vulnerability allows high privileged attacker with network access via multiple 
    protocols to compromise MySQL Cluster. Successful attacks of this vulnerability can result in 
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Cluster.
    (CVE-2024-20965)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

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

mysql_check_version(variant:'Cluster', fixed:'7.6.29', min:'7.6', severity:SECURITY_WARNING);
