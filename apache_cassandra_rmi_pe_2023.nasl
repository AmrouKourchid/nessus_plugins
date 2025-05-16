#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181676);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2023-30601");

  script_name(english:"Apache Cassandra 4.0.x < 4.0.10 / 4.1.x < 4.1.2 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A database running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"Privilege escalation when enabling FQL/Audit logs allows user with JMX access to run arbitrary commands as the user 
running Apache Cassandra. This issue affects Apache Cassandra: from 4.0.0 through 4.0.9, from 4.1.0 through 4.1.1. The 
vulnerability requires nodetool/JMX access to be exploitable, disable access for any non-trusted users. Upgrade to 
4.0.10 or 4.1.2 and leave the new FQL/Auditlog configuration property allow_nodetool_archive_command as false.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.apache.org/thread/f74p9jdhmmp7vtrqd8lgm8bq3dhxl8vn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85dfb019");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Cassandra version 4.0.10, 4.1.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:cassandra");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_cassandra_remote_detection.nbin", "apache_cassandra_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Cassandra");

  exit(0);
}

include('vcf.inc');

var app = 'Apache Cassandra';

get_install_count(app_name:app, exit_if_zero:TRUE);

var app_info = vcf::combined_get_app_info(app:app);

var constraints =
[
  { 'min_version' : '4.0.0', 'fixed_version' : '4.0.10' },
  { 'min_version' : '4.1.0', 'fixed_version' : '4.1.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
