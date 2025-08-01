#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72215);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2014-1610");
  script_bugtraq_id(65223);

  script_name(english:"MediaWiki < 1.19.11 / 1.21.5 / 1.22.2 Multiple Remote Code Execution Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running
on the remote host is affected by the following remote code execution
vulnerabilities :

  - A user-input validation error exists during thumbnail
    generation in the 'thumb.php' script that allows the
    execution of arbitrary shell commands via a specially
    crafted DjVu file.

  - A user-input validation error exists in the
    'pdfhandler_body.php' script used by the PdfHandler
    extension that allows the execution of arbitrary shell
    commands via a specially crafted PDF file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number. Also
note that the affected features are not enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2014/Feb/6");
  # https://www.checkpoint.com/threatcloud-central/articles/2014-01-28-tc-researchers-discover.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8ca1fc8");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.21");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22");
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-January/000140.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92483abd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.19.11 / 1.21.5 / 1.22.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1610");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MediaWiki thumb.php page Parameter Remote Shell Command Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MediaWiki Thumb.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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

# Check Point says the DjVu issue affects 1.8 onwards.
if (
  version =~ "^1\.[89]\." ||
  version =~ "^1\.1[0-8]\." ||
  version =~ "^1\.19\.([0-9]|10)([^0-9]|$)" ||
  version =~ "^1\.21\.[0-4]([^0-9]|$)" ||
  version =~ "^1\.22\.[01]([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.11 / 1.21.5 / 1.22.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
