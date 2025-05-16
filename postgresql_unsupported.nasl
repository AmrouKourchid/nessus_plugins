#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63347);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");
  script_xref(name:"IAVA", value:"0001-A-0583");

  script_name(english:"PostgreSQL Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a database
server.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
PostgreSQL on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/support/versioning/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of PostgreSQL that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"This version of the software is no longer supported.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_keys("installed_sw/PostgreSQL", "Settings/ParanoidReport");
  script_require_ports("Services/postgresql", 5432);
  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include('vcf_extras_postgresql.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = 'PostgreSQL';
var port = get_service(svc:"postgresql", default:5432);

var kb_base = 'database/' + port + '/postgresql/';
var kb_ver = NULL;
var kb_path = kb_base + 'version';
var ver = get_kb_item(kb_path);
if (!empty_or_null(ver)) kb_ver = kb_path;

var app_info = vcf::postgresql::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_base:kb_base);
vcf::check_granularity(app_info:app_info, sig_segments:2);

var version = app_info['version'];
var source = app_info['path'];
var database = app_info['database'];

ver = split(version, sep:'.');
for (var i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ( ver[0] < 13 ) ||
  ( ver[0] == 13 && ver[1] <= 19)
)
{
  register_unsupported_product(product_name:"PostgreSQL",
                               cpe_base:"postgresql:postgresql", version:version);

  if (report_verbosity > 0)
  {
    var report = '';
    if(database)
      report += '\n  Database name     : ' + database ;
    report +=
      '\n  Version source     : ' + source +
      '\n  Installed version  : ' + version +
      '\n  Supported versions : 13 / 14 / 15 / 16 / 17\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
