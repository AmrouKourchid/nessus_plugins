#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##
include("compat.inc");

if (description)
{
  script_id(191048);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_name(english:"OpenVPN Server Client Web Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"An OpenVPN Client Web Server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an OpenVPN Client Web Server.");
  script_set_attribute(attribute:"see_also", value:"https://openvpn.net/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
	script_set_attribute(attribute:"asset_categories", value:"Remote Management and Monitoring");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 943); 

  exit(0);
}

include('http.inc');
include('install_func.inc');

var version = UNKNOWN_VER;
var product_name = 'OpenVPN CWS';
var resp = NULL;

var port = get_http_port();

# detect qdocroot info
resp = http_send_recv3(
    method       : 'GET',
    port         : port,
    item         : '/',
    exit_on_fail : FALSE,
    follow_redirect : 3
);

dbg::log(msg:'Sent: ' + http_last_sent_request());
dbg::log(msg:'Recv: ' + resp[0] + resp[1] + resp[2]);

if ('200' >!< resp[0])
  audit(AUDIT_NOT_DETECT, product_name);

# no webserver response on the port then, audit out
if(empty_or_null(resp[2])) audit(AUDIT_NOT_DETECT, product_name);

var dashboard_detect = pregmatch(string:resp[2],pattern:'OpenVPN CWS', icase: TRUE);
# no UI then we audit out.
if (empty_or_null(dashboard_detect)) audit(AUDIT_NOT_DETECT, product_name);

register_install(
  app_name        : 'OpenVPN CWS',
  path            : '/',
  version         : version,
  port            : port,
  webapp          : TRUE,
  vendor          : 'OpenVPN',
  product         : 'Client Web Server',
  cpe             : 'cpe:/a:openvpn:clientwebserver'
);

# report out that we found OpenVPN CWS running
report_installs(app_name:product_name, port:port);