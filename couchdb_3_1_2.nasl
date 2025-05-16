#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182208);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/02");

  script_cve_id("CVE-2021-38295");

  script_name(english:"Apache CouchDB < 3.1.2 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote host is prior 3.1,2. It is, therefore, affected
by a privilege escalation vulnerability. A malicious user with permission to create documents in a database is able to
attach a HTML attachment to a document. If a CouchDB admin opens that attachment in a browser, e.g. via the CouchDB
admin interface Fauxton, any JavaScript code embedded in that HTML attachment will be executed within the security
context of that admin. A similar route is available with the already deprecated _show and _list functionality. This
privilege escalation vulnerability allows an attacker to add or remove data in any database or make configuration
changes. 

Note that Nessus did not actually test for these flaws but instead, has relied on the version in CouchDB's banner.");
  script_set_attribute(attribute:"see_also", value:"https://docs.couchdb.org/en/stable/cve/2021-38295.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CouchDB 3.1.2 and apply the recommended settings, or upgrade to 3.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38295");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:couchdb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("couchdb_detect.nasl");
  script_require_keys("www/couchdb");
  script_require_ports("Services/www", 5984, 6984);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:5984);
var app = vcf::get_app_info(app:'couchdb', webapp:TRUE, port:port);


# Require paranoia for 3.1.2 because they may have the new security setting enabled
var constraints = [
  {'max_version' : '3.1.1', 'fixed_display' : 'See vendor advisory'},
  {'equal' : '3.1.2', 'fixed_display' : 'See vendor advisory', 'require_paranoia': TRUE}
];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_WARNING
);
