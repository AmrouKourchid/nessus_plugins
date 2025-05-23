#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132079);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/02");

  script_cve_id("CVE-2019-2974", "CVE-2020-2780", "CVE-2021-2144");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"MariaDB 5.5.x < 5.5.66 Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is 5.5.x prior to 5.5.66. It is, therefore, affected by a denial
of service vulnerability in the following Oracle MySQL components: InnoDB, Optimizer and PS. An authenticated, remote 
attacker can exploit this issue, to cause a hang or frequently repeatable crash of MySQL Server.");
  # https://mariadb.com/kb/en/library/mariadb-5566-release-notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c608c2a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.66 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2144");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2780");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include('mysql_version.inc');

mysql_check_version(variant: 'MariaDB', min:'5.5.0-MariaDB', fixed:make_list('5.5.66-MariaDB'), severity:SECURITY_WARNING);
