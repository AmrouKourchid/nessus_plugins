#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181680);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2021-26919");

  script_name(english:"Apache Druid < 0.20.2 RCE");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"Apache Druid allows users to read data from other database systems using JDBC. This functionality is to allow trusted
users with the proper permissions to set up lookups or submit ingestion tasks. The MySQL JDBC driver supports certain
properties, which, if left unmitigated, can allow an attacker to execute arbitrary code from a hacker-controlled
malicious MySQL server within Druid server processes. This issue was addressed in Apache Druid 0.20.2

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/f1k8hm3sdrmng8637wdsg3w9539bn8zc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Druid version 0.20.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:druid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_druid_detect.nbin");
  script_require_keys("installed_sw/Apache Druid");

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:8081);
var app_info = vcf::get_app_info(app:'Apache Druid', port:port, service:TRUE);

var constraints = [
  {'fixed_version' : '0.20.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
