#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18690);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_name(english:"Moodle Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a course management system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Moodle, an open source course (or learning)
management system written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://moodle.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('install_func.inc');

var port = get_http_port(default:80, php:TRUE);
var app = "Moodle";

# Loop through directories.
if (thorough_tests) 
  var dirs = list_uniq(make_list("/moodle", cgi_dirs()));
else dirs = make_list(cgi_dirs());

var installs = 0;
var dir;
foreach dir (dirs)
{
  # Request index.php.
  var url = dir + '/index.php';
  var res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  dbg::detailed_log(lvl:3, msg:'Request sent: ' + '\n' + http_last_sent_request());
  dbg::detailed_log(lvl:3, msg:'Response received: ' + '\n' + res[0] + '\n' + res[1] + '\n' + res[2]);

  var url_pattern = '<a [^>]*href="http://moodle\\.org/"[^>]*><img [^>]*src="[^>]*/moodlelogo(\\.gif)?"';
  # If it looks like Moodle...
  if (
    (
      pgrep(pattern:"me\.name\.replace\(\/\^moodle-\/,\'\'\)", string:res[2]) &&
      pgrep(pattern:'moodle":{"name":"moodle","base', string:res[2])

    ) ||
    (
      pgrep(pattern:'^Set-Cookie: *MoodleSession(Test)?=[a-zA-Z0-9]+;', string:res[1]) &&
      pgrep(pattern:url_pattern, string:res[2])
    ) ||
    (
      pgrep(pattern:'^Set-Cookie: *MOODLEID_=[%a-fA-F0-9]+;', string:res[1]) &&
      pgrep(pattern:url_pattern, string:res[2])
    ) ||
    (
      'var moodleConfigFn = function' >< res[2] &&
      '<a href="#skipavailablecourses" class="skip-block">Skip available courses</a>' >< res[2]
    ) ||
    (
      '/help.php?module=moodle&amp;file=cookies.html&forcelang=' >< res[2] &&
      '<input type="hidden" name="testcookies" value="1"' >< res[2]
    ) ||
    pgrep(pattern:url_pattern, string:res[2])
  )
  {
    var version = NULL;

    # Try to extract the version number from the banner.
    var pat = '<a title="moodle ([0-9][^"]+)" href="http://moodle\\.org/"';
    var matches = pgrep(pattern:pat, string:res[2], icase:TRUE);
    var match, item;
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = pregmatch(pattern:pat, string:match, icase:TRUE);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    # If that didn't work, try to get it from the release notes.
    if (isnull(version))
    {
      url = dir + "/lang/en/docs/release.html";
      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

      # nb: ignore patterns like "Moodle 1.5 (to be released shortly)"
      pat = "^<h2>Moodle (.+) \([0-9]";
      matches = pgrep(pattern:pat, string:res[2], icase:TRUE);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = pregmatch(pattern:pat, string:match, icase:TRUE);
          if (!isnull(item))
          {
            version = item[1];
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (empty_or_null(version)) version = UNKNOWN_VER;

    installs++;

    register_install(
      vendor   : "Moodle",
      product  : "Moodle",
      app_name : app,
      port     : port,
      path     : dir,
      version  : version,
      cpe      : "cpe:/a:moodle:moodle",
      webapp   : TRUE
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
