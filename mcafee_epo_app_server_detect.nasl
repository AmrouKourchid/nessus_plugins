#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66318);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/14");

  script_xref(name:"IAVT", value:"0001-T-0858");

  script_name(english:"Trellix ePolicy Orchestrator Application Server Detection");
  script_summary(english:"Looks for the ePO App Server login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web management interface for a security management application was
detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"ePolicy Orchestrator (ePO) Application Server, a web interface for ePO,
was detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.trellix.com/products/epo/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

var app_name = 'epo_app_server';
var cpe = 'cpe:/a:mcafee:epolicy_orchestrator';
var page = '/core/orionSplashScreen.do';
var port = get_http_port(default:8443);
var dir = '';

var res = http_send_recv3(method:'GET', item:dir + page, port:port, exit_on_fail:TRUE);

dbg::detailed_log(lvl:2, msg:'Request sent: ' + http_last_sent_request());
dbg::detailed_log(lvl:2, msg:'Response recv: ' + res[0] + res[1] + res[2]);

var match = pregmatch(string:res[2], pattern:"ePolicy Orchestrator(?:\s-\sOn-prem|)\s([\d.]+)", icase:TRUE, multiline:TRUE);

if (isnull(match))
  audit(AUDIT_WEB_APP_NOT_INST, 'ePO Application Server', port);

var ver = match[1];

register_install(
  app_name:app_name,
  path:dir + page,
  port:port,
  version:ver,
  webapp:TRUE,
  cpe:cpe
);
report_installs(app_name:app_name, port:port);
