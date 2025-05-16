#TRUSTED 93d5efce615742fd42859fade3942bb7a3446079bf737d3f397e73ff1779e5a79af85e25c2ea04cf5c3dead8111c20d045b86a564de9bfa5253666c90af46226505c842c3b383374466b03a7f7c1cabc3418b1280fefb2820abd4e6f2b3504cbeb738ee0d73fc083489104ae33b492d5fd8581539da1923e5e55e918b908958f6e67f78fb41a9462a1ae382cefd5cd102ed0ee79665b6b24c4d39863a49af7b3a5add59267c66f72cd0485d7c5692180e36254ddf2dafc7a936646e99579e5420a827f803b237784d5914ffd1cae43805dfbc10784797688d0f6f700c836b9fca6c96af19f9af6435886e411e4c94dd8a46461bc696070c7a4b803f6859116c58095584ccf0862658659a088ccb951de91d77652697ea373af7c8cd93a1b5d447bde8ef10f6dcef276151e32d30b07b36d1b12db624f3b5933db22ba2fd09471bf5fc36ef893a4f5438d880565be97bd33892479e911e3446e549e413b03d7bd5a35c35b83a1bfa52c56aa1def49228c51d43bf5c186f4905f889a7936a302736b0fcc5fd82b7fcdd6d1b84fc53c6cd0815a678370eb7e7934e47a97e1c782ca3deb0def5fd7bb9c671770fb60ca6c51b7eb23bb4c99f66d34b1f3f19ecce7de36cc141a13478e0a6328c998bbe9218ffe775bfa91fff65c7b75621e4ac36064543c04d0f41b5b6fe9e57ae6c9dc2a03077d8125facb83bd8254893219ca49f3
#TRUST-RSA-SHA256 72e586c816b2a4e7eee4d1ae7e803f02ef2bad1e9003cc911e7f38fc1c12e9dd799a691fdc7ca69dbc1273c8c2927117a7dced41d4c4f253eb0856cf664db076b321676df81020ffebb7b46f40948edb2e849f78c3a132640db645712d03ee673f1e03f28acb8e554156a17975bdc8e92c7a6256395f5b594882441bd436f14a5782e020f95050121b21065ace7e5c2b2244bb912e8737a33a571dd718fc79114c804f61250115621f74b52d8855b9d323fab7b59f423d6ee4e923bc6e409ada221e351aa45a703a6c42a2bac1be4819b2c97dadff34552d3d59393242faaf9c6533df4f4525e7c3cf9b7094fbc64a72cef6b8f44f05eb9cd94b9d347de4a82a1f29f8fd57146327bc741f97e5eefd61427167962b3728e8bc0dcfdfc5da826f7220a378cc6a6dfa9ec007d93d752e4e0e744f7784792619ebfd93d055efb817d3eabb70367b2172c60e396e39503041ec464b281f13259d4d413c0a2943e43bd76b46a15cf118f493d9333c7605bc8b3871ab44e36df3a26b54e832a2f9abd874efb02a08f1887a25c306a2f5f327ebb4070987a54f8fdc135eea24c9ff1690bb914e3e281fe70ceb6e800ad1d422373cf4a79657cd3be3062f1a85f559efc50b4e77fdd188aad1a8a71309a5f5c07101eacb0c0db6e12eed209f3930ac70e154abc6ade3588bac3e65af412328c03aafc42e8e4c9caa4c88f4f1da7aa42c92
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45577);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/27");
  script_xref(name:"IAVT", value:"0001-T-0763");

  script_name(english:"Atlassian JIRA Detection");

  script_set_attribute(attribute:"synopsis", value:
"An issue tracker is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Atlassian JIRA, a web-based issue tracker written in Java, is running
on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.atlassian.com/software/jira");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

##
# A workaround function that allows us to add extra data to installations after they have been registered.
# The added data won't be included in report solely after calling this function.
# @param app_name Name of the application to add extra to - basically always 'Atlassian JIRA' here.
# @param port Port used by the installation we're adding data to.
# @param extra Extra array that should be added to the kb data.
# @param path Web application path that Jira uses
# @return IF_OK if successful, IF_ERROR otherwise
## 
function jira_add_extra(app_name, port, extra, path)
{
  var app_kb_key = make_app_kb_key(app_name:app_name, port:port);
  if (app_kb_key[0] != IF_OK) return IF_ERROR;
  app_kb_key = app_kb_key[1];

  if(empty_or_null(path)) path = '/';

  # Generate install KB key.
  var install_kb_key = make_install_kb_key(app_kb_key:app_kb_key, path:path);
  if (install_kb_key[0] != IF_OK) return IF_ERROR;
  install_kb_key = install_kb_key[1];
  
  add_extra_to_kb(install_kb_key:install_kb_key, extra:extra);
  return IF_OK;
}

##
# A slightly adapted get_install_report from webapp_func.inc.
# It was modified to allow passing Jira edition for each detected instance.
# @param display_name Name of the web application being reported on - basically always 'Atlassian JIRA' here.
# @param installs Installs to report. This should be an array that [add_install] returns.
# @param port Port number of the web server where the app was detected.
# @param jira_editions An array of {path:Jira edition string} containing Jira edition for each detected instance.
# @return A report of installs detected if any were detected, NULL otherwise.
##
function jira_get_report(display_name, installs, port, jira_editions)
{
  var info, version, n, dir, dirs, url, report;

  if (isnull(display_name))
  {
    err_print("jira_get_report() missing required argument 'display_name'.");
    return NULL;
  }
  else if (isnull(port))
  {
    err_print("jira_get_report() missing required argument 'port'.");
    return NULL;
  }

  # Bail out if there's nothing to report (i.e. nothing was detected)
  if (isnull(installs) || max_index(keys(installs)) == 0) return NULL;

  info = "";
  n = 0;

  foreach version (sort(keys(installs)))
  {
    info += strcat('\n  Version : ', version, '\n');
    dirs = split(installs[version], sep:SEPARATOR, keep:FALSE);

    foreach dir (sort(dirs))
    {
      dir = base64_decode(str:dir);

      info += strcat('  URL     : ', build_url(port:port, qs:dir), '\n');
      info += strcat('  Edition : ', jira_editions[dir], '\n');
      n++;
    }
  }

  report = '\nThe following instance';
  if (n == 1) report += ' of ' + display_name + ' was';
  else report += 's of ' + display_name + ' were';
  report += ' detected on the remote host :\n' + info;

  return report;
}

var app = "Atlassian JIRA";
# Put together a list of directories we should check for JIRA in.
var dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, "/jira");
  dirs = list_uniq(dirs);
}

# Put together checks for different pages that we can scrape version
# information from.
var checks = make_array();

# This covers older versions.
var regexes = make_list();
regexes[0] = make_list("please notify your JIRA administrator of this problem");
regexes[1] = make_list(">Version *: ([0-9.]+)");
checks["/500page.jsp"] = regexes;

# This covers newer versions.
regexes = make_list();
regexes[0] = make_list(
  '<a +(class="seo-link" +rel="nofollow" +)?href="https?://www\\.atlassian\\.com/software/jira"( +class="smalltext")? *>(Atlassian +JIRA|Project +Management +Software)</a *>'
);
regexes[1] = make_list(
  '<meta +name="ajs-version-number" +content="([0-9.]+)" *>',
  '<input +type="hidden" +title="JiraVersion" +value="([0-9.]+)" */>',
  '<span +id="footer-build-information"[^>]*>\\(v([0-9.]+)[^<]+</span *>',
  "Version *: *([0-9.]+)"
);
checks["/login.jsp"] = regexes;

# This covers the REST API for the 4.x series.
regexes = make_list();
regexes[0] = make_list('"baseUrl" *:', '"version" *:', '"scmInfo" *:');
regexes[1] = make_list('"version" *: *"([0-9.]+)"');
checks["/rest/api/2.0.alpha1/serverInfo"] = regexes;

# This covers the REST API for the 5.x series.
checks["/rest/api/2/serverInfo"] = regexes;

# Get the ports that webservers have been found on, defaulting to
# JIRA's default port.
var port = get_http_port(default:8080);

# Find where JIRA is installed.
var installs = find_install(appname:app, checks:checks, dirs:dirs, port:port, cpe:'cpe:/a:atlassian:jira');

if (isnull(installs))
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

var jira_editions = {};
foreach(var serialized_paths in installs)
{
  foreach(var b64_path in split(serialized_paths, sep:';', keep:FALSE))
  {
    var path = base64_decode(str:b64_path);
    var about_page = http_send_recv3(method:'GET', port:port, item:trim(path, rchars:'/') + '/secure/AboutPage.jspa');
    var jira_edition = 'Unknown';
    if(!empty_or_null(about_page[2]))
    {
      about_page = about_page[2];
      if ('enabled-feature-keys' >< about_page)
      {
        jira_edition = 'Jira Server';
        if('jira.cluster.monitoring.show.offline.nodes' >< about_page) jira_edition = 'Jira Data Center';
      }
    }

    # Manual workaround - find_install() automatically detects installations and calls register_install(), but it doesn't
    # let us pass extra info, so we need to add it somehow after the installation is saved to KB
    jira_add_extra(app_name:app, port:port, path:path, extra:{'Edition':jira_edition});
    jira_editions[path] = jira_edition;
  }
}

# Report our findings.
var report = jira_get_report(
      display_name  : app,
      installs      : installs,
      port          : port,
      jira_editions : jira_editions
    );
security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
