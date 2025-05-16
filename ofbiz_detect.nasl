##
# (C) Tenable, Inc.
##

include('compat.inc');


if (description)
{
  script_id(59245);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_name(english:"Apache OFBiz Detection");

  script_set_attribute(attribute:"synopsis", value:
"A web application framework was detected on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Apache OFBiz is an open source enterprise resource planning (ERP)
system.  One or more web applications bundled with OFBiz were
detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://ofbiz.apache.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:open_for_business_project");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include('http.inc');
include('ssl_funcs.inc');
include('webapp_func.inc');

##
# Ofbiz only shows major and minor version. Patch is not available.
# Version is not available on 16 and below.
# Providing credentials does not provide any additional information.
##

var vendor = 'Apache';
var product = 'OFBiz';
var app_name = vendor + ' ' + product;
var port = get_http_port(default:8443);
var url = '/webtools/control/main'; 

# Apache OfBiz only runs with ssl.
var transport = ssl_transport();

var res = http_send_recv3(method:'GET', port:port, item:url, transport:transport);

if (!empty_or_null(res) && !empty_or_null(res[2]))
{
  var matches = pregmatch(pattern:'[Aa]pache.*OFBiz', string:str_replace(string:res[2], find:'\n', replace:''));

  if(empty_or_null(matches))
    audit(AUDIT_NOT_INST, app_name);

  set_kb_item(name:'www/ofbiz/port', value:port);

  matches = pregmatch(pattern:"Release\s*(\d+\.\d+)", string:str_replace(string:res[2], find:'\n', replace:''));

  var version = UNKNOWN_VER;
  if(!empty_or_null(matches))
    version = matches[1];

  register_install(
    app_name : app_name,
    vendor   : vendor,
    product  : product,
    port     : port,
    path     : url,
    version  : version,
    webapp   : TRUE,
    cpe      : 'cpe:/a:apache:open_for_business_project'
  );

  report_installs(app_name:app_name, port:port);
}
else
  audit(AUDIT_NOT_INST, app_name);