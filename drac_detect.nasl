#
# (C) Tenable, Inc.
#

# Thanks to Jason Haar for his help!


include('compat.inc');

if (description)
{
  script_id(51185);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/03");

  script_xref(name:"IAVT", value:"0001-T-0580");

  script_name(english:"Dell Integrated Remote Access Controller (iDRAC) Web Interface Detection");

  script_set_attribute(attribute:"synopsis", value:
"The web interface for Dell iDRAC was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web interface for Dell Integrated Remote Access Controller (iDRAC),
formerly known as Dell Remote Access Controller (DRAC), was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/en-us/lp/dt/open-manage-idrac");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:idrac9");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:idrac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:idrac7");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac9_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac8_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac7_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac6_firmware");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac9");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac8");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac7");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac6");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");

  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "httpver.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('hardware_registration.inc');
include('host_os.inc');
include('http.inc');
include('os_install.inc');


namespace dell_idrac
{
  # Server generation to iDRAC version
  var servergen_to_version_mapping = {
    '15G' : '9',
    '14G' : '8',
    '13G' : '8',
    '12G' : '7',
    '11G' : '6' 
  };

  ##
  # Wrapper function to make HTTP GET request and log HTTP response.
  #
  # @param [item:str]             URL path
  # @param [follow_redirect:int]  Maximum number of redirects to follow (default: 0) (optional)
  # @param [exit_on_fail:bool]    Exits if http_send_recv3() fails (default: false) (optional)
  #
  # @return HTTP response array from http_send_recv3() if successful
  #         NULL if an error occurred
  ##
  function request_and_log_response(item, follow_redirect, exit_on_fail)
  {
    if (empty_or_null(item))
      return NULL;

    var res = http_send_recv3(method:'GET', port:port, item:item, follow_redirect:follow_redirect, exit_on_fail:exit_on_fail);
    log_response(item:item, res:res);

    return res;
  }

  ##
  # Log HTTP response.
  #
  # @param [item:str]  URL path
  # @param [res:array] HTTP response array from http_send_recv3()
  #
  # @return true if successful
  #         false if unsuccessful
  ##
  function log_response(item, &res)
  {
    if (empty_or_null(item) || empty_or_null(res))
      return false;

    var data = strcat(
      '\n',
      'Response Code: ',     res[0],
      'Response Headers:\n', res[1],
      'Response Body:\n',    res[2]
    );

    dbg::detailed_log(
      lvl : 3,
      msg : strcat('http_send_recv3() response for ', item, '\n'),
      msg_details : {
        values : { lvl:3, value:data }
      }
    );

    return true;
  }

  ##
  # Retrieve Service Tag and MAC address from the Redfish API metadata
  #
  # @param [array:array reference] Array to upate with results from the parsed API response
  #
  # @remark The Redfish was introduced in iDRAC 8 and is enabled by default.
  #
  # @return true if successful
  #         false if unsuccessful
  ##
  function retrieve_redfish_api_metadata(&array)
  {
    var item = '/redfish/v1/';
    var res = dell_idrac::request_and_log_response(item:item);

    if (empty_or_null(res) || res[1] !~ 'Content-Type: *application/json' || empty_or_null(res[2]))
    {
      dbg::detailed_log(lvl:1, msg:'Response is an unexpected format for ' + item);
      return NULL;
    }

    var json = deserialize(res[2]);
    var attributes = json.Oem.Dell;

    if (empty_or_null(attributes))
    {
      dbg::detailed_log(lvl:1, msg:'Response is an unexpected format for ' + item);
      return NULL;
    }

    array['MAC Address'] = attributes['ManagerMACAddress'];
    array['Service Tag'] = attributes['ServiceTag'];

    return true;
  }
}

##
# Main
##

# Set HTTP configuration
#  - iDRAC is fragile and we do not want to miss it, increase timeout.
http_set_read_timeout(get_read_timeout() * 2);
http_set_gzip_enabled(TRUE);

# Variable declaration
var drac_detected = FALSE;
var fw_ver = UNKNOWN_VER;
var drac_version = UNKNOWN_VER;

var os_extra = {};
var hw_extra = {};

var link, match, drac_gen, ver, res, build, fw_build;
var json, attributes;

var port = get_http_port(default: 443, embedded: TRUE);

# Get the index page (usually redirected)
#  - The index page is used as the basis for further processing depending on the version of iDRAC.
var page = dell_idrac::request_and_log_response(item:'/', follow_redirect:2, exit_on_fail:TRUE);

##
# Check for a Javascript redirect
#  - In some cases, versions 5, 6, and 7 use a JavaScript redirect we will manually look for and handle the redirect
##
if (
  'function redirect()' >< page[2] ||
  '"javascript:redirect();"' >< page[2]
)
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 5/6/7');

  # iDRAC 6/7 examples:
  # top.document.location.href= "/login.html";
  # top.document.location.href = "/index.html";
  if (page[2] =~ 'top\\.document\\.location\\.href(\\s)?= "/(index|login)\\.html"')
  {
    link = '/login.html';
  }
  else
  {
    match = pregmatch(pattern:'top\\.document\\.location\\.replace\\("(.*)"\\)', string:page[2]);
    if (!empty_or_null(match))
      link = match[1];
  }

  if (link)
    page = dell_idrac::request_and_log_response(item:link, exit_on_fail:TRUE);
}

##
# iDRAC 8 / 9
#  - require ajax to display version info on about page
##
if(
  '/session?aimGetProp=fwVersionFull' >< page[2] ||
  page[2] =~ "gen_iDrac[\d+]"
)
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 8 or 9');
  drac_detected = TRUE;

  # There may be some fingerprint overlap between 7 and 8. To solve that, we try retrieve the prodServerGen
  #  - This does not appear to work for iDRAC 9 anymore
  res = dell_idrac::request_and_log_response(item:'/data?get=prodServerGen');

  if (!empty_or_null(res[2]))
  {
    drac_gen = pregmatch(string:res[2], pattern:'<prodServerGen>(\\d+G)</prodServerGen>');
    if (!isnull(drac_gen))
    {
      drac_gen = drac_gen[1];
      dbg::detailed_log(lvl:1, msg:'iDRAC Generation: ' + drac_gen);

      drac_version = dell_idrac::servergen_to_version_mapping[drac_gen];
    }
  }

  # Retrieve the edition
  #  - Example: <prodClassName>Express</prodClassName>
  res = dell_idrac::request_and_log_response(item:'/data?get=prodClassName');

  if (!empty_or_null(res[2]))
  {
    match = pregmatch(string:res[2], pattern:'<prodClassName>([^<]+)</prodClassName>');
    if (!isnull(match))
      os_extra['Edition'] = trim(match[1]);
  }

  if (drac_version == UNKNOWN_VER)
  {
    # Multiple versions may be present on a page, we need to parse the page for the highest version.
    if ('gen_iDrac8' >< page[2])
      ver = '8';
    else if ('gen_iDrac7' >< page[2])
      ver = '7';
    else if ('gen_iDrac6' >< page[2])
      ver = '6';

    if (!empty_or_null(ver)) drac_version = ver;
  }

  # Retrieve the firmware version and build
  #  - iDRAC 8 example: fwVersionFull" :"2.30.30.30 (Build 50)
  res = dell_idrac::request_and_log_response(item:'/session?aimGetProp=fwVersionFull');

  match = pregmatch(pattern:'fwVersionFull.+?([0-9.]+)(\\s*\\(Build\\s([0-9]+))?', string:res[2]);

  if (!empty_or_null(match))
  {
    fw_ver   = match[1];
    fw_build = match[3];
  }

  # Retrieve Service Tag and MAC address from the Redfish API metadata
  dell_idrac::retrieve_redfish_api_metadata(array:hw_extra);
}

##
# iDRAC 9
##
if ('idrac-start-screen' >< page[2])
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 9');

  # GET request to '/restgui/locale/strings/locale_str_en.json'
  res = dell_idrac::request_and_log_response(item:'/restgui/locale/strings/locale_str_en.json');

  # Extract iDRAC version (e.g. 8, 9)
  match = pregmatch(string:res[2], pattern:'"app_title":\\s*"iDRAC(\\d+)"');
  if (!isnull(match))
  {
    drac_version = match[1];
    drac_detected = TRUE;
  }

  # GET request to 'sysmgmt/2015/bmc/info'
  res = dell_idrac::request_and_log_response(item:'/sysmgmt/2015/bmc/info');

  if (!empty_or_null(res) && res[1] =~ 'Content-Type: *application/json' && !empty_or_null(res[2]))
  {
    json = deserialize(res[2]);

    attributes = json.Attributes;
    if (!empty_or_null(attributes))
    {
                                         # Examples:
      fw_ver   = attributes.FwVer;         # "FwVer" : "6.10.30.20",
      fw_build = attributes.BuildVersion;  # "BuildVersion" : "03",

      os_extra['Edition']      = attributes.License;         # "License" : "Datacenter",
      hw_extra['System Model'] = attributes.SystemModelName; # "SystemModelName" : "PowerEdge R650",

      if (empty_or_null(drac_version))
      {
        drac_gen = attributes.ServerGen;  # "ServerGen" : "15G",
        drac_version = dell_idrac::servergen_to_version_mapping[drac_gen];
      }
      else
      {
        dbg::detailed_log(lvl:1, msg:'Response is an unexpected format for /sysmgmt/2015/bmc/info');
      }
    }
  }

  # Retrieve Service Tag and MAC address from the Redfish API metadata
  dell_idrac::retrieve_redfish_api_metadata(array:hw_extra);
}

##
# iDRAC 6 / 7
##
else if (
  page[2] =~ "<title>(Integrated)?((\s)?Dell)? Remote Access Controller [0-9]+" ||
  page[2] =~ 'eLang.getString\\("STR_DEFAULT_DOMAIN"\\)\\s*\\+\\s*"iDRAC[67]"'
)
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 6/7');

  drac_detected = TRUE;

  res = dell_idrac::request_and_log_response(item:'/public/about.html');

  if (!res[2] || 'Remote Access Controller' >!< res[2])
    res = dell_idrac::request_and_log_response(item:'/Applications/dellUI/Strings/EN_about_hlp.htm');

  if (res[2] =~ 'Remote Access Controller [0-9]+')
  {
    match = pregmatch(pattern:'Remote Access Controller ([0-9]+)', string:res[2]);

    if (!empty_or_null(match))
      drac_version = match[1];
    else
      drac_version = '6, 7 or later';

    match = pregmatch(pattern:'var fwVer = "([0-9.]+)(\\(Build [0-9]+\\))?"', string:res[2]);

    if (empty_or_null(match))
      match = pregmatch(pattern:"Version\s*([0-9.]+)[\s\n]*<", string:res[2]);

    if (!empty_or_null(match[1]))
      fw_ver = match[1];

    if (!empty_or_null(match[2]))
      fw_build = match[2];
  }
}

##
# DRAC 5
#  - GET request to '/cgi/lang/en/login.xsl'
#  - GET request to '/cgi-bin/webcgi/about'
##
else if (
  page[2] =~ '\\<IpAddress\\>([0-9\\.]+)\\</IpAddress\\>' &&
  '<drac>' >< page[2] && '</drac>' >< page[2]
)
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 5');

  res = dell_idrac::request_and_log_response(item:'/cgi/lang/en/login.xsl');

  if ('Dell Remote Access Controller' >< res[2])
  {
    drac_detected = TRUE;

    match = pregmatch(pattern:'strProductName"\\>DRAC ([0-9]+)\\<', string:res[2]);

    if (!empty_or_null(match))
      drac_version = match[1];
    else
      drac_version = '5 or earlier';

    # Get DRAC version from /cgi-bin/webcgi/about
    var res2 = dell_idrac::request_and_log_response(item:'/cgi-bin/webcgi/about');

    if ('<drac>' >< res2[2])
    {
      build = pregmatch(pattern:"<FirmwareVersion>([0-9\.]+)</FirmwareVersion>", string:res2[2]);
      if (!empty_or_null(build))
        fw_ver = build[1];
    }
  }
}

##
# DRAC 4
##
else if ('<title>Remote Access Controller</title>' >< page[2])
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for iDRAC 4');

  drac_detected = TRUE;
  ver = pregmatch(pattern:'var s_oemProductName = "DRAC ([0-9]+)"', string:page[2]);

  if (!empty_or_null(ver))
    drac_version = ver[1];
  else
    drac_version = '4 or earlier';

  res = dell_idrac::request_and_log_response(item:'/cgi/about');

  build = pregmatch(pattern:'var s_build = "([0-9\\.]+) \\(Build .*', string:res[2]);
  if (!empty_or_null(build))
    fw_ver = build[1];
}

# DRAC/MC (Dell Remote Access Controller/Modular Chassis)
var pat = "Dell\(TM\) Remote Access Controller/Modular Chassis\</title\>";
if (page[2] =~ pat)
{
  dbg::detailed_log(lvl:1, msg:'Potential fingerprints for DRAC/MC');
  drac_detected = TRUE;

  # Grab version from /about.html
  res = dell_idrac::request_and_log_response(item:'/about.htm');
  if (res[2] =~ pat)
  {
    drac_version = 'DRAC/MC';

    ver = pregmatch(pattern:"Version .* &nbsp;([0-9\.]+) \(Build .*\)\<", string:res[2]);
    if (!empty_or_null(ver))
      fw_ver = ver[1];
  }
}

# Product not detected
if (!drac_detected)
  audit(AUDIT_WEB_APP_NOT_INST, 'iDRAC', port);

# DRAC is detected on 443, but NAT or RP may be in place
var disabled_port, cache;
if (port != 80)
{
  # Play on the safe side: disable port 80 too.
  disabled_port = 80;
  cache = http_get_cache(port: disabled_port, item: '/');
  if ( 'HTTP/1.1 301 ' >< cache &&
       egrep(string: cache, pattern: '^Location: *https://.*/start.html') )
  {
    declare_broken_web_server(port:disabled_port, reason:'iDRAC web interface is fragile.');
  }
}

# Firmware with build appended (e.g. 2.20.20.20.42)
#  - Note: this is needed for existing downstream plugins.
var fw_ver_build = UNKNOWN_VER;

if (!empty_or_null(fw_ver))
{
  fw_ver_build = fw_ver;
  if (!empty_or_null(fw_build))
    fw_ver_build += '.' + fw_build;
}

replace_kb_item(name:'Host/Dell/iDRAC', value:TRUE);
replace_kb_item(name: 'Services/www/' + port + '/embedded', value: TRUE);

##
# Register application
#  - Note: this is needed for existing downstream plugins.
##
register_install(
  vendor   : 'Dell',
  product  : 'Remote Access Card',
  port     : port,
  app_name : 'iDRAC',
  path     : '/',
  version  : drac_version,
  extra    : make_array('Firmware Version', fw_ver_build),
  webapp   : TRUE,
  cpe      : 'cpe:/h:dell:remote_access_card'
);

##
# Register OS
##
var type    = 'remote';
var method  = 'web interface';
var conf    = 95;

var vendor  = 'Dell';
var product = 'iDRAC';

var os_name = strcat(vendor, ' ', product);
if (!empty_or_null(drac_version))
  os_name += ' ' + drac_version;

# Base CPE
#  - Examples:
#    cpe:/o:dell:idrac9_firmware:4.20.20.20
#    cpe:/o:dell:idrac8_firmware:2.70.70.70
var cpe = 'cpe:/o:dell:idrac';

# Product version (e.g. 8, 9)
if (!empty_or_null(drac_version))
  cpe += drac_version;

cpe += '_firmware';

os_extra['Firmware Version'] = fw_ver;
os_extra['Firmware Build']   = fw_build;

register_os(
  type        : type,
  port        : port,
  method      : method,
  confidence  : conf,

  vendor      : vendor,
  product     : product,

  release     : drac_version,
  version     : fw_ver,
  update      : fw_build,
  os_name     : os_name,
  cpe         : cpe,
  extra       : os_extra
);

host_os_add(method:'iDRAC_web_interface', os:os_name, confidence:95, type:'embedded');

##
# Register hardware
##

# CPE
#  - Examples:
#    cpe:/h:dell:idrac9:-
#    cpe:/h:dell:idrac8:-
cpe = 'cpe:/h:dell:idrac';

# Product version (e.g. 8, 9)
if (!empty_or_null(drac_version))
  cpe += drac_version;

register_hardware(
  type        : type,
  port        : port,
  method      : method,
  confidence  : conf,

  category    : 'BMC',

  full_name   : os_name,
  vendor      : vendor,
  product     : product,
  cpe         : cpe,

  product_number   : drac_version,
  hardware_uuid    : hw_extra['Service Tag'],
  firmware_version : os_extra['Firmware Version'],

  extra : hw_extra
);

report_installs(app_name:'iDRAC', port:port);