###
# (C) Tenable, Inc.
###

include("compat.inc");


if (description)
{
  script_id(44319);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/10");

  script_name(english:"D-Link Router Detection");
  script_summary(english:"Detects D-Link Routers");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is a D-Link router.");
  script_set_attribute(attribute:"description", value:
"The remote device is a D-Link router.  These devices route packets and
may provide port forwarding, DMZ configuration and other networking
services.");
  script_set_attribute(attribute:"see_also", value:"http://www.dlink.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-604_broadband_router");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dsl-124");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dsl-320b");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dsl-2750b");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dsl-2750u");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dva-g3670b");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dvm-321");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:wbr-1310");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-300");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-600");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-610");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-615");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-615t");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-615s");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-652");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-655");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-657");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-685");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-803");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-806a");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-818lw");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-819");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-822");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-825");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-825acg1");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-842");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-843");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-850l");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-853");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-855l");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-860l");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-862l");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-865l");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-866l");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-1210");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-1260");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:wbr-2200");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dap-1533");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-835");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dhp-1565");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:dlink:dap-1650");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:dlink:dhp-1320");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8080, 443, 8443);

  exit(0);
}

include("oui.inc");
include('http.inc');
include("mac_address_func.inc");
include('webapp_func.inc');

function detect_with_ui_option_one()
{
  var result = {detected:FALSE};

  var portuguese=FALSE, spanish=FALSE, chinese=FALSE, korean=FALSE;

  res = http_send_recv3(method:'GET', item:'/', port:port, follow_redirect : 2, exit_on_fail:TRUE);

  ##
  # The value within the HTML <title> tag will vary slightly depending
  # on the device model. 
  ##

  if (!isnull(res[2]))
  {
    if (service_is_unknown(port:port)) register_service(port:port, proto:"www");

    if ("<VendorName>D-Link Systems</VendorName>" >< res[2])
    {
      if ("<ModelName>" >< res && "</ModelName>" >< res[2])
      {
        modelname = strstr(res[2], "<ModelName>") - "<ModelName>";
        modelname = modelname - strstr(modelname, "</ModelName>");
        extra['Model'] = modelname;
        replace_kb_item(name:"d-link/model", value:modelname);
      }

      if ("<ModelDescription>" >< res[2] && "</ModelDescription>" >< res[2])
      {
        modeldesc = strstr(res[2], "<ModelDescription>") - "<ModelDescription>";
        modeldesc = modeldesc - strstr(modeldesc, "</ModelDescription>");
        extra['Description'] = modeldesc;
      }

      if ("<FirmwareVersion>" >< res[2] && "</FirmwareVersion>" >< res[2])
      {
        firmware = strstr(res[2], "<FirmwareVersion>") - "<FirmwareVersion>";
        firmware = firmware - strstr(firmware, "</FirmwareVersion>");
        extra['Firmware'] = firmware;
        replace_kb_item(name:"d-link/firmware", value:firmware);
      }
      
      # Instead of reporting everything that has D-Link Systems/Corporation in the title,
      # Check that atleast one of the following was caught otherwise not detected
      if (!empty_or_null(modelname) || !empty_or_null(firmware))
      {
        replace_kb_item(name:"www/d-link", value:TRUE);
        replace_kb_item(name:"www/"+port+"/d-link", value:TRUE);
        replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
        
        result = {'detected':TRUE};
      }
    }
    else if ('D-LINK SYSTEMS, INC' >< res[2] || 'D-LINK CORPORATION, INC' >< res[2] || 'D-Link System, Inc' >< res[2] || 'D-Link Systems, Inc' >< res[2] || 'D-Link Corporation' >< res[2])
    { 

      # Let's attempt to figure out the language used
      if ("Versão de Firmware" >< res[2] || "versão de firmware" >< res[2]) portuguese=TRUE;
      else if ("Versión del firmware" >< res[2] || "versión del firmware" >< res[2]) spanish=TRUE;
      else if ("韌體版本" >< res[2]) chinese=TRUE;
      else if ("펌웨어 버전" >< res[2]) korean=TRUE;


      if (portuguese)
      {
        # Firmware Version
        var fwver_option_1_portuguese = pregmatch(string:res[2], pattern:">Versão de Firmware(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?([\w.]+)");
        if (!isnull(fwver_option_1_portuguese)) firmware = fwver_option_1_portuguese[1];

        if(empty_or_null(firmware))
        {
          var fwver_option_2_portuguese = pregmatch(string:res[2], pattern:">Versão de Firmware\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
          if (!isnull(fwver_option_2_portuguese)) firmware = fwver_option_2_portuguese[1];
        }

        
        # Hardware Version
        var hwver_option_1_portuguese = pregmatch(string:res[2], pattern:">?Versão de Hardware(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?(?:rev\s)?([\w.]+)");
        if (!isnull(hwver_option_1_portuguese)) hardware = hwver_option_1_portuguese[1];

        if (empty_or_null(hardware))
        {
          var hwver_option_2_portuguese = pregmatch(string:res[2], pattern:">Versão de Hardware\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
          if (!isnull(hwver_option_2_portuguese)) hardware = hwver_option_2_portuguese[1];
        }
      }

      if (spanish)
      {
        # Firmware Version
        var fwver_option_1_spanish = pregmatch(string:res[2], pattern:">Versión del firmware(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?([\w.]+)");
        if (!isnull(fwver_option_1_spanish)) firmware = fwver_option_1_spanish[1];

        if(empty_or_null(firmware))
        {
          var fwver_option_2_spanish = pregmatch(string:res[2], pattern:">Versión del firmware\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
          if (!isnull(fwver_option_2_spanish)) firmware = fwver_option_2_spanish[1];
        }

        # Hardware Version
        var hwver_option_1_spanish = pregmatch(string:res[2], pattern:">?Versión de hardware(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?(?:rev\s)?([\w.]+)");
        if (!isnull(hwver_option_1_spanish)) hardware = hwver_option_1_spanish[1];

        if (empty_or_null(hardware))
        {
          var hwver_option_2_spanish = pregmatch(string:res[2], pattern:">Versión de hardware\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
          if (!isnull(hwver_option_2_spanish)) hardware = hwver_option_2_spanish[1];
        }
    
      }

      if (chinese)
      {
        # Firmware Version
        var fwver_option_1_chinese = pregmatch(string:res[2], pattern:">韌體版本(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?([\w.]+)");
        if (!isnull(fwver_option_1_chinese)) firmware = fwver_option_1_chinese[1];

        if(empty_or_null(firmware))
        {
          var fwver_option_2_chinese = pregmatch(string:res[2], pattern:">韌體版本\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
          if (!isnull(fwver_option_2_chinese)) firmware = fwver_option_2_chinese[1];
        }

        # Hardware Version
        var hwver_option_1_chinese = pregmatch(string:res[2], pattern:">?硬體版本(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?(?:rev\s)?([\w.]+)");
        if (!isnull(hwver_option_1_chinese)) hardware = hwver_option_1_chinese[1];

        if (empty_or_null(hardware))
        {
          var hwver_option_2_chinese = pregmatch(string:res[2], pattern:">硬體版本\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
          if (!isnull(hwver_option_2_chinese)) hardware = hwver_option_2_chinese[1];
        }
      }

      if (korean)
      {
        # Firmware Version
        var fwver_option_1_korean = pregmatch(string:res[2], pattern:">펌웨어 버전(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?([\w.]+)");
        if (!isnull(fwver_option_1_korean)) firmware = fwver_option_1_korean[1];

        if(empty_or_null(firmware))
        {
          var fwver_option_2_korean = pregmatch(string:res[2], pattern:">펌웨어 버전\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
          if (!isnull(fwver_option_2_korean)) firmware = fwver_option_2_korean[1];
        }

        # Hardware Version
        var hwver_option_1_korean = pregmatch(string:res[2], pattern:">?하드웨어 버전(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?(?:rev\s)?([\w.]+)");
        if (!isnull(hwver_option_1_korean)) hardware = hwver_option_1_korean[1];

        if (empty_or_null(hardware))
        {
          var hwver_option_2_korean = pregmatch(string:res[2], pattern:">하드웨어 버전\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
          if (!isnull(hwver_option_2_korean)) hardware = hwver_option_2_korean[1];
        }
      }
      ##
      # MODEL language doesnt matter here
      ##

      var current_prod_match_1 = pregmatch(string:res[2], pattern:'<a href=["\'].*support.dlink.com.*>(\\w+-\\w+)');
      if (!isnull(current_prod_match_1)) modelname = current_prod_match_1[1];
      
      if ('>Product Page :' >< res[2])
      {
        if ('<div class="pp">Product Page :' >< res[2])
        {
          modelname = strstr(res[2], '<div class="pp">Product Page :') - '<div class="pp">Product Page : ';
          modelname = modelname - strstr(modelname, '<a href');
        }
        else if ('<span class="product">Product Page :' >< res[2])
        {
          modelname = strstr(res[2], '<span class="product">Product Page :') - '<span class="product">Product Page : ';
          modelname = strstr(modelname, '>') - '>';
          modelname = modelname - strstr(modelname, '</a>');
        }
      }

      if (empty_or_null(modelname))
      {
        var model_match_2 = pregmatch(string:res[2], pattern:'var ModemVer=["\'](\\w+-\\w+)["\']');
        if (!isnull(model_match_2)) modelname = model_match_2[1];
      }

      if (empty_or_null(modelname))
      {
        var model_match_3 = pregmatch(string:res[2], pattern:">[\n]?Product (?:Page)?(?:<\/span>)?:\s?(\w+-\w+)");
        if (!isnull(model_match_3)) modelname = model_match_3[1];
      }


      if (modelname)
      {
        extra['Model'] = modelname;
        replace_kb_item(name:"d-link/model", value:modelname);
      }

      ##
      # FIRMWARE VERSION
      ##

      # RegEx patterns handle different firmware version based on changes to web interface
      # Only one of these will match at a time

      if (empty_or_null(firmware))
      {
        var latest_fwver_match = pregmatch(string:res[2], pattern:'<script>show_words\\(sd_FWV\\)</script>:\\s([\\w.]+)');
        if (!empty_or_null(latest_fwver_match)) firmware = latest_fwver_match[1];
        
        if (empty_or_null(firmware))
        {
          var legacy_fwver_match = pregmatch(string:res[2], pattern:'class="fwv".*> *: *([\\w.]+) *<span id="fw_ver"');
          if (!empty_or_null(legacy_fwver_match)) firmware = legacy_fwver_match[1];
        }
      }
      if (empty_or_null(firmware))
      {
        var fwver_option_3 = pregmatch(string:res[2], pattern:'>Firmware Version:[\\n\\s]+([\\d+]+)\\.(?:<span.*)?">?([\\w.]+)');
        if (!empty_or_null(fwver_option_3))
        {
          if (!empty_or_null(fwver_option_3[1]) && !empty_or_null(fwver_option_3[2]))
          {
            firmware = fwver_option_3[1] + "." + fwver_option_3[2];
          }
          # In this case the EU/DE/US can be found seperately and will be appended to firmware if found
          var fwver_extend = pregmatch(string:res[2], pattern:'var fw_extend_ver = "([\\w.]+)"');
          if (!empty_or_null(fwver_extend) && !empty_or_null(firmware)) firmware = firmware + fwver_extend[1];
        }
      }
      
      if (empty_or_null(firmware))
      {
        var fwver_option_4 = pregmatch(string:res[2], pattern:">[\s]?Firmware Version(?:<\/span>)?(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s]?([\w.]+)");
        if (!isnull(fwver_option_4)) firmware = fwver_option_4[1];
      }
      if (empty_or_null(firmware))
      {
        var fwver_option_5 = pregmatch(string:res[2], pattern:'var FirmwareVer=["\']([\\w.]+)["\']');
        if (!isnull(fwver_option_5)) firmware = fwver_option_5[1];
      }
      if (empty_or_null(firmware))
      {
        var fwver_option_6 = pregmatch(string:res[2], pattern:">Firmware Version\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
        if (!isnull(fwver_option_6)) firmware = fwver_option_6[1];
      }

      if (firmware)
      {
        extra['Firmware'] = firmware;
        replace_kb_item(name:"d-link/firmware", value:firmware);
      }

      ##
      # HARDWARE VERSION
      ##

      # RegEx patterns handle different hardware version based on changes to web interface
      if (empty_or_null(hardware))
      {
        var latest_hwver_match = pregmatch(string:res[2], pattern:'<script>show_words\\(TA3\\)</script>:\\s([\\w.]+)');
        if (!isnull(latest_hwver_match)) hardware = latest_hwver_match[1];
      }
      if (empty_or_null(hardware))
      {
        var hwver_option_2 = pregmatch(string:res[2], pattern:'var HardwareVer=["\']([\\w.]+)["\']');
        if (!isnull(hwver_option_2)) hardware = hwver_option_2[1];
      }
      if (empty_or_null(hardware))
      {
        var hwver_option_3 = pregmatch(string:res[2], pattern:">?Hardware Version(?:&nbsp;)?\s?:\s?(?:&nbsp;)?[\s\n]?(?:rev\s)?([\w.]+)");
        if (!isnull(hwver_option_3)) hardware = hwver_option_3[1];
      }
      if (empty_or_null(hardware))
      {
        var hwver_option_4 = pregmatch(string:res[2], pattern:">Hardware Version\s?:[\n\s]+.*\n?.*>([\w.]+)<\/span>");
        if (!isnull(hwver_option_4)) hardware = hwver_option_4[1];
      }
      
      if (hardware)
      {
        extra['Hardware'] = hardware;
        replace_kb_item(name:"d-link/hardware", value:hardware);
      }

      # Instead of reporting everything that has D-Link Systems/Corporation in the title,
      # Check that atleast one of the following was caught otherwise not detected
      if (!empty_or_null(modelname) || !empty_or_null(firmware) || !empty_or_null(hardware))
      {
        replace_kb_item(name:"www/d-link", value:TRUE);
        replace_kb_item(name:"www/"+port+"/d-link", value:TRUE);
        replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
        result = {'detected':TRUE};
      }
    }
  }
  return result;
}

function detect_with_ui_option_two()
{
  var result = {detected:FALSE};
  # Lets try a differnt way of detecion , based on another UI variant
  var item = "/devinfo?area=notice|net|version";

  res = http_send_recv3(
    method       : 'GET',
    port         : port,
    item         : item,
    exit_on_fail : FALSE,
    follow_redirect : 2
  );

  if (!empty_or_null(res[2]))
  {
    # In these particular interfaces we can also grab the deviceMac address and confirm it is a D-Link device 
    # by matching it with our mac addresses in oui.inc and matching on either: 
    # D-Link International
    # D-Link Corporation
    # D-LINK SYSTEMS, INC.

    var macaddress_match = pregmatch(string:res[2], pattern:'"deviceMac":\\s?"(\\w.+)"');
    if (!isnull(macaddress_match))
    {
      var oui_lines = split(oui, keep: 0);

      oui_lines = sort(oui_lines);

      var mac_address = macaddress_match[1];
      # Lets try to match it with our mac addresses in oui.inc and confirm its a d-link product
      # since nothing else can gaurantee that this page we get back is for D-Link and to avoid FP's
      var e = ereg_replace(string: mac_address, pattern: "^(..):(..):(..):.*", replace: "\1\2\3 ");
      e = toupper(e);
      var line = my_bsearch(v: oui_lines, e: e);
      if (line)
      {
        var mac_vendor = chomp(substr(line, 7));
      }
    }

    # If we have the vendor name and it matches , continue to check for model/firmware/hardware
    if (!empty_or_null(mac_vendor) && ("D-Link" >< mac_vendor || "D-LINK" >< mac_vendor))
    {
      extra['Mac Vendor'] = mac_vendor;
      # match model name (always seems present)
      var model_match = pregmatch(string:res[2], pattern:'"modelName":\\s?"(\\w.+)"');
      if (!isnull(model_match))
      {
        modelname = model_match[1];
        extra['Model'] = modelname;
        replace_kb_item(name:"d-link/model", value:modelname);
      }

      # also always seems present
      var firmware_match = pregmatch(string:res[2], pattern:'"version":\\s?"(\\w.+)"');
      if (!isnull(firmware_match))
      {
        firmware = firmware_match[1];
        extra['Firmware'] = firmware;
        replace_kb_item(name:"d-link/firmware", value:firmware);
      }

      var hardware_match = pregmatch(string:res[2], pattern:'"hwRevision":\\s?"(\\w.+)"');
      if (!isnull(hardware_match))
      {
        hardware = hardware_match[1];
        extra['Hardware'] = hardware;
        replace_kb_item(name:"d-link/hardware", value:hardware);
      }
      # Instead of reporting everything that has D-Link Systems/Corporation in the file,
      # Check that atleast one of the following was caught otherwise not detected
      if (!empty_or_null(modelname) || !empty_or_null(firmware) || !empty_or_null(hardware))
      {
        replace_kb_item(name:"www/d-link", value:TRUE);
        replace_kb_item(name:"www/"+port+"/d-link", value:TRUE);
        replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
        result = {'detected':TRUE};
      }
    }
  }
  return result;
}

function detect_with_ui_option_three()
{
  var result = {detected:FALSE};
  var item = '/ayefeaturesconvert.js';

  res = http_send_recv3(
    method       : 'GET',
    port         : port,
    item         : item,
    exit_on_fail : FALSE
  );

  if (!empty_or_null(res[2]) && ("D-Link International" >< res[2] || "D-Link Corporation"  >< res[2] || "D-LINK SYSTEMS, INC."  >< res[2]))
  {
    var model_match_special_case = pregmatch(string:res[2], pattern:'var AYECOM_PROFILE=["\'](\\w.+)["\']');
    if (!isnull(model_match_special_case))
    {
      modelname = model_match_special_case[1];
      extra['Model'] = modelname;
      replace_kb_item(name:"d-link/model", value:modelname);
    }

    var firmware_match_special_case = pregmatch(string:res[2], pattern:'var AYECOM_FWVER=["\'](\\w.+)["\']');
    if (!isnull(firmware_match_special_case))
    {
      firmware = firmware_match_special_case[1];
      extra['Firmware'] = firmware;
      replace_kb_item(name:"d-link/firmware", value:firmware);
    }

    var hardware_match_special_case = pregmatch(string:res[2], pattern:'var AYECOM_HWVER=["\'](\\w.+)["\']');
    if (!isnull(hardware_match_special_case))
    {
      hardware = hardware_match_special_case[1];
      extra['Hardware'] = hardware;
      replace_kb_item(name:"d-link/hardware", value:hardware);
    }
    # Instead of reporting everything that has D-Link Systems/Corporation in the title,
    # Check that atleast one of the following was caught otherwise not detected
    if (!empty_or_null(modelname) || !empty_or_null(firmware) || !empty_or_null(hardware))
    {
      replace_kb_item(name:"www/d-link", value:TRUE);
      replace_kb_item(name:"www/"+port+"/d-link", value:TRUE);
      replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
      result = {'detected':TRUE};
    }
  }
  return result;
}

##
# Main
##

var app = 'D-Link Routers';
var cpe = 'cpe:/h:dlink';
var extra = make_array();
var port = get_http_port(default:8080);
var modelname, modeldesc, hardware, res, firmware;

var result = detect_with_ui_option_one();
if (!result.detected) result = detect_with_ui_option_two();
if (!result.detected) result = detect_with_ui_option_three();
if (!result.detected) audit(AUDIT_WEB_APP_NOT_INST, app, port);

if (empty_or_null(firmware)) firmware = UNKNOWN_VER;

register_install(
  vendor    : "D-Link",
  product   : "D-Link Routers",
  app_name  : app,
  path      : '/',
  port      : port,
  version   : firmware,
  webapp    : TRUE,
  extra     : extra,
  cpe       : cpe
);

report_installs(app_name:app, port:port);

