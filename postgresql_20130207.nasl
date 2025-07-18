#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64669);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2013-0255");
  script_bugtraq_id(57844);

  script_name(english:"PostgreSQL 8.3 < 8.3.23 / 8.4 < 8.4.16 / 9.0 < 9.0.12 / 9.1 < 9.1.8 / 9.2 < 9.2.3 Denial of Service");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 8.3.x prior
to 8.3.23, 8.4.x prior to 8.4.16, 9.0.x prior to 9.0.12, 9.1.x prior to
9.1.8 or 9.2 prior to 9.2.3.  It is, therefore, potentially affected by
a denial of service vulnerability due to a flaw in the enum_recv()
function of 'backend/utils/adt/enum.c'.  By exploiting this flaw, a
remote attacker could crash the affected application.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1446/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.3/release-8-3-23.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.4/release-8-4-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.0/release-9-0-12.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-8.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.2/static/release-9-2-3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 8.3.23 / 8.4.16 / 9.0.12 / 9.1.8 / 9.2.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"postgresql", default:5432, exit_on_fail:TRUE);

version = get_kb_item_or_exit('database/'+port+'/postgresql/version');
source = get_kb_item_or_exit('database/'+port+'/postgresql/source');
database = get_kb_item('database/'+port+'/postgresql/database_name');

get_backport_banner(banner:source);
if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, 'PostgreSQL server');

ver = split(version, sep:'.');
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 8 && ver[1] == 3 && ver[2] < 23) ||
  (ver[0] == 8 && ver[1] == 4 && ver[2] < 16) ||
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 12) ||
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 8) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    report = '';
    if(database)
      report += '\n  Database name     : ' + database ;
    report +=
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.3.23 / 8.4.16 / 9.0.12 / 9.1.8 / 9.2.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
