#%NASL_MIN_LEVEL 80900
##
# Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232290);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/07");

  script_name(english:"Gradio UI Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is a Gradio UI platform.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Gradio UI web application");
  script_set_attribute(attribute:"see_also", value:"https://www.gradio.app/guides/quickstart");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gradio-app:gradio");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 7860); 

  exit(0);
}

include('http.inc');
include("http_func.inc");
include('install_func.inc');
include('ssl_funcs.inc');

var version = UNKNOWN_VER;
var product_name = 'Gradio';

var port = get_http_port(default:7860);

var user, pass;
user = get_kb_item("http/login");
pass = get_kb_item("http/password");

 # Get version and build information if credentials were supplied
if (!empty_or_null(user) && !empty_or_null(pass))
{
  var encaps = get_port_transport(port);
  var secure = TRUE;

  if (empty_or_null(encaps) || encaps <= ENCAPS_IP)
  {
    secure = FALSE;
    dbg::detailed_log(lvl:1, msg:'An authenticated request to the Gradio UI API has failed because the HTTP transport is insecure.'); 
  }

  # Handle self-signed certificates
  var transport = ssl_transport(ssl:TRUE, verify:FALSE);

  if (secure)
  {
    var auth_resp, xml_resp, vami_resp;
    var data, token, credential;
    
    # Base64 encode basic authentication and set cookie.
    credential = strcat('Basic ', base64(str:user + ':' + pass));

    # Initialize cookiejar
    init_cookiejar();

    # Set authorization header
    set_http_cookie(name:'Authorization', value:credential);
  }
}

# detect UI
var resp = http_send_recv3(
  method       : 'GET',
  port         : port,
  item         : '/',
  exit_on_fail : TRUE, 
  follow_redirect: TRUE
);

if ('401' >< resp[0])
 audit(AUDIT_MISSING_CREDENTIALS, 'Gradio UI on port ' + port);
else if ('200' >!< resp[0])
  audit(AUDIT_NOT_DETECT, product_name);

# no webserver response on the port then, audit out
if(empty_or_null(resp[2])) audit(AUDIT_NOT_DETECT, product_name);

var dashboard_detect = pregmatch(string:resp[2],pattern:'gradio_config');
var _detect1 = pregmatch(string:resp[2],pattern:'window.gradio_config');
var _detect2 = pregmatch(string:resp[2],pattern:'gradio-app');
var _detect3 = pregmatch(string:resp[2],pattern:'data-gradio-mode');

# if there are absolutely no matches then we audit out.
if (
    empty_or_null(dashboard_detect) && 
    empty_or_null(_detect1) && 
    empty_or_null(_detect2) && 
    empty_or_null(_detect3)
  ) audit(AUDIT_NOT_DETECT, product_name);

# searching for this string --> window.gradio_config = {"version": "5.12.0",
version = pregmatch(string:resp[2],
  pattern: 'window.gradio_config = {"version":"([0-9]+\\.[0-9]+\\.[0-9]+)",'
  );

if(empty_or_null(version)) version = UNKNOWN_VER;
else version = version[1];

register_install(
  app_name        : product_name,
  path            : '/',
  version         : version,
  port            : port,
  webapp          : TRUE,
  cpe             : 'cpe:/a:gradio-app:gradio'
);

# report out that we found the webapp running
report_installs(app_name:product_name, port:port);