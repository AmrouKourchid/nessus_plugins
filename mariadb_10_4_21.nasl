#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152115);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/06");

  script_cve_id("CVE-2021-2372", "CVE-2021-2389", "CVE-2021-46658");
  script_xref(name:"IAVA", value:"2021-A-0333-S");

  script_name(english:"MariaDB 10.4.0 < 10.4.21 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.4.21. It is, therefore, affected by multiple
vulnerabilities as referenced in the mdb-10421-rn advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2021-2372)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
    affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2021-2389)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mdb-10421-rn");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.4.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2389");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'10.4.0-MariaDB', fixed:make_list('10.4.21-MariaDB'), severity:SECURITY_HOLE);