#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181681);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2020-1958");

  script_name(english:"Apache Druid < 0.17.1 LDAP Injection");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"When LDAP authentication is enabled in Apache Druid 0.17.0, callers of Druid APIs with a valid set of LDAP credentials
can bypass the credentialsValidator.userSearch filter barrier that determines if a valid LDAP user is allowed to
authenticate with Druid. They are still subject to role-based authorization checks, if configured. Callers of Druid
APIs can also retrieve any LDAP attribute values of users that exist on the LDAP server, so long as that information
is visible to the Druid server. This information disclosure does not require the caller itself to be a valid LDAP user.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/lpx8vxt898k60pl308q1gqbvwj9w49f3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Druid version 0.17.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1958");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:druid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_druid_detect.nbin");
  script_require_keys("installed_sw/Apache Druid", "Settings/ParanoidReport");

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:8081);
var app_info = vcf::get_app_info(app:'Apache Druid', port:port, service:TRUE);

# Can't check if LDAP auth is enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  {'fixed_version' : '0.17.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
