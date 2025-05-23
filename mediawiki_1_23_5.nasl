#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78109);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2014-7295");
  script_bugtraq_id(70238);

  script_name(english:"MediaWiki < 1.19.20 / 1.22.12 / 1.23.5 'includes/OutputPage.php' XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MediaWiki application running on
the remote host is affected by an input validation error in the
'includes/OutputPage.php' script related to JavaScript in CSS content.
This can be exploited to conduct cross-site scripting (XSS) attacks.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-October/000163.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30a52eab");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.20");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22#MediaWiki_1.22.12");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.5");
  script_set_attribute(attribute:"see_also", value:"https://phabricator.wikimedia.org/T72672");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2014/q4/67");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.19.20 / 1.22.12 / 1.23.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7295");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/MediaWiki", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
version = install['version'];
install_url = build_url(qs:install['path'], port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^1\.19\.(\d|1[0-9])([^0-9]|$)" ||
  version =~ "^1\.22\.(\d|1[01])([^0-9]|$)"  ||
  version =~ "^1\.23\.[0-4]([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.20 / 1.22.12 / 1.23.5' +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
