# netscaler_web_detect.nasl
# GPLv2
#
# History:
#
# 1.00, 11/21/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title (9/23/09)
# - Added CPE and updated copyright (10/18/2012)

include("compat.inc");

if (description)
{
  script_id(29222);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_xref(name:"IAVT", value:"0001-T-0571");

  script_name(english:"Citrix Application Delivery Controller (ADC) / Citrix NetScaler Detection");
  script_summary(english:"Detects NetScaler web management interface");

  script_set_attribute(attribute:"synopsis", value:
"A Citrix ADC web management interface is running on this port.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Citrix ADC (previously NetScaler), an appliance for web
application delivery, and the remote web server is its management
interface.");
  script_set_attribute(attribute:"see_also", value:"https://www.citrix.com/products/citrix-adc/");
  script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service.nasl","find_service1.nasl","httpver.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("install_func.inc");

var app_name = "Citrix ADC / NetScaler";
var cpe = "cpe:/a:citrix:netscaler";
var port = get_http_port(default:443, embedded:TRUE);
var extra;
var failedDetect;
var url = "/";
var detection_dbg = [];
var none = "Does not exist.";


var resp = http_get_cache_ka(port:port, item:url);
detection_dbg['Initial Response'] = resp + '\n' + '\n';

if('302' >< resp)
{
   # build target url for http_send_recv3
   url = "/logon/LogonPoint/index.html";
   var https_req_resp = http_send_recv3(item:url, method:'GET', follow_redirect:2, port:port);
   if (!empty_or_null(https_req_resp[2]) && ">Citrix Gateway</title>" >< https_req_resp[2])
   {
    resp = https_req_resp[2];
   }
   else
   {
    resp = '';
   }

   if (!empty_or_null(resp))
   {
     detection_dbg['Citrix Check - 1'] = pgrep(pattern:'>www.citrix.com</a>',string:resp,icase:TRUE);
     detection_dbg['Citrix Check - 2'] = pgrep(pattern:'>Citrix Gateway</title>',string:resp,icase:TRUE);
   }
   else
   {
     detection_dbg['Citrix Check - 1'] = none;
     detection_dbg['Citrix Check - 2'] = none;
   }
}
    
# no 302 scenario
if(empty_or_null(resp))
{
  url = "/index.html";
  resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:url,port:port),
                              embedded:TRUE);
  detection_dbg['Request 1'] = resp + '\n' + '\n';
}

if(empty_or_null(resp))
{
  url = "/vpn/index.html";
  resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:url,port:port),
                              embedded:TRUE);
  detection_dbg['Request 2'] = resp + '\n' + '\n';
}

dbg::detailed_log(lvl:3, msg: "[ + ] Target Information : " + '\n' + obj_rep(detection_dbg));

if (isnull(resp)) exit(1, "The web server on port "+port+" failed to respond.");

var match1=pgrep(pattern:"<title>(Citrix Login|Citrix Access Gateway)</title>",string:resp,icase:TRUE);
var match2=pgrep(pattern:'action="(/login/do_login|/ws/login\\.pl|/cgi/login)"',string:resp,icase:TRUE);
var match3=pgrep(pattern:'>www.citrix.com</a>',string:resp,icase:TRUE);
var match4=pgrep(pattern:'>Citrix Gateway</title>',string:resp,icase:TRUE);
var match5=pgrep(pattern:"Citrix Systems, Inc.", string:resp, icase:TRUE);

var matches = [];
if ((match1 && match2) || (match3 && match4) || (match4 && match5))
{
  matches['match1'] = match1;
  matches['match2'] = match2;
  matches['match3'] = match3;
  matches['match4'] = match4;
  matches['match5'] = match5;

  dbg::detailed_log(lvl:3, msg: "[ + ] Patterns detected : " + '\n' + obj_rep(matches));
  
  replace_kb_item(name:"www/netscaler", value:TRUE);
  replace_kb_item(name:"www/netscaler/"+port, value:TRUE);
  replace_kb_item(name:"www/netscaler/"+port+"/initial_page", value:url);
  replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

  #check for ADC specificially
  if( "<span>Citrix ADC</span>" >< resp)
  {
    extra = {"Product":"Citrix ADC"};
  }
  failedDetect = "The plugin did not attempt to detect the version.";

  register_install(app_name: app_name, 
                    vendor : 'Citrix',
                    product : 'NetScaler Application Delivery Controller',
                    path: url, 
                    port: port, 
                    extra: extra,
                    cpe: cpe, 
                    webapp:TRUE);
}
else
{
  audit(AUDIT_NOT_DETECT, app_name, port);
}

report_installs(app_name:app_name, port:port, extra:failedDetect);

