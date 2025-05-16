#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
 script_id(71430);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/18");

  script_xref(name:"IAVT", value:"0001-T-0553");

 script_name(english:"Cisco IOS XR Version");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the IOS XR version number of the remote
Cisco device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running IOS XR, an operating system for high-end
carrier-grade Cisco routers. 

It is possible to read the IOS XR version number by connecting to the
router using SSH or SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc");

 exit(0);
}

include('cisco_kb_cmd_func.inc');
include('hardware_registration.inc');
include('os_install.inc');
include('structured_data.inc');

function grab_serial_number(show_inventory)
{
  if(empty_or_null(show_inventory)) return NULL;

  var sn_regex = '"Rack 0"(?:.|\\s)*?SN: (\\S+)';
  var serial_number = pregmatch(string:show_inventory, pattern:sn_regex, multiline:TRUE);

  if(!empty_or_null(serial_number)) serial_number = serial_number[1];
  else serial_number = NULL;
  
  return serial_number; 
}

function line_card()
{
  # Lets get the ine card first
  local_var buf = get_kb_item('Host/Cisco/Config/show_platform');

  # Now check if we failed to get the line card
  if (!check_cisco_result(buf))
  {
    dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:' Unable to retrieve line card information. \n\n');
    dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:' buf: ' +  obj_rep(buf) + '\n\n');
    return NULL;
  }

  # show platform usually have the following pattern:
  #Wed Jul  3 11:34:18.487 UTC
  #Node            Type                      State            Config State
  #-----------------------------------------------------------------------------
  #0/RP0/CPU0      ASR-9922-RP-SE(Active)    IOS XR RUN       PWR,NSHUT,MON
  #0/RP1/CPU0      ASR-9922-RP-TR(Standby)   IOS XR RUN       PWR,NSHUT,MON
  #0/FT0/SP        FAN TRAY                  READY
  #0/FT1/SP        FAN TRAY                  READY
  #0/0/CPU0        A9K-36x10GE-TR            IOS XR RUN       PWR,NSHUT,MON
  #0/1/CPU0        A9K-36x10GE-SE            IOS XR RUN       PWR,NSHUT,MON
  #0/PM0/SP        PWR-3KW-AC-V2             READY            PWR,NSHUT,MON
  #0/FC0/SP        ASR-9912-SFC110           OK               PWR,NSHUT,MON

  local_var pat = "0\/\w+\/\w+\s+(\w+-\w+-\w+-*\w*)\S*\s+";

  local_var split = split(buf, keep:false);

  local_var line_cards = '';
  local_var line = '';

  foreach line (split)
  {
    local_var match = pregmatch(pattern:pat, string:line);

    if (isnull(match)) continue;

    if (match[1] >< line_cards) continue;

    line_cards += match[1] + ',';
  }
  set_kb_item(name:'Host/Cisco/IOSXR/line_cards', value:line_cards);

}

function remove_leading_zero(s)
{
  local_var str, temp, parts, part;
  parts = split(s, sep:".", keep:FALSE);
  foreach part (parts)
  {
    temp = ereg_replace(pattern:"^0*", replace:"", string:part);
    if (temp == "") temp = "0";
    if (str) str = str + "." + temp;
    else str = temp;
  }
  return str;
}

function test(s, ssh, port, proto)
{
  local_var v, l, m, ver, image;
  local_var     os, type, source;
  local_var matches, model, report;
  var serial_number;
  var snc, id_data;
  var show_inventory = get_kb_item("Host/Cisco/Config/show_inventory");

  if (isnull(proto)) proto = 'tcp';

  if (!s) return NULL;

  # SSH / SNMP detection
  # nb: see "IOS XR Numbering" section in
  #     http://www.cisco.com/en/US/prod/collateral/iosswrel/ps8802/ps6968/ps6350/whitepaper_C11-719867.html
  l = pgrep(pattern:"^.* IOS[ -]XR Software.*Version [0-9]+\.[0-9.]+", string:s);
  if (!strlen(l)) return;

  v = pregmatch(string:l, pattern:"(?: \(Cisco ([^)]+)\))?, *Version +([0-9]+\.[0-9.]+)");
  if (isnull(v)) return NULL;

  ver = chomp(v[2]);

  # Remove leading 0's from the version
  ver = remove_leading_zero(s:ver);

  set_kb_item(name:"Host/Cisco/IOS-XR/Version", value:ver);

  # SSH parse model
  if (ssh)
  {
    matches = pregmatch(string:l, pattern:"^cisco ([^(]+) \([^)]+\) processor");
    if (matches)
      model = matches[1];
    else
    {
      # Try looking globally on the configuration
      matches = pregmatch(string:s, pattern:"(^|\r?\n)cisco ([^(]+) \([^)]+\) processor");
      if (matches)
        model = matches[2];
      else
      {
        matches = pregmatch(string:s, pattern:"cisco ([^(]+) \(.* processor");
        if (matches)
          model = matches[1];
      }
    }
    # execute show platform and check for Line card
    line_card();
  }
  # SNMP parse model
  else
  {
    if (!isnull(v[1]))
    {
      model = v[1];
    }

    # Check for an alternative pattern
    #  - Examples:
    #   Cisco IOS XR Software (IOS-XRv 9000), Version 7.0.2
    #   Cisco IOS XR Software (NCS-5500), Version 6.3.3
    #   Cisco IOS XR Software (NCS540L), Version 7.0.2
    else if (empty_or_null(model))
    {
      matches = pregmatch(string:l, pattern:"\(([A-Z -]+[^)]+)\),", icase:TRUE);
      if (!empty_or_null(matches))
        model = matches[1];
    }
  }

  # Create a separate variable for register_hardware() to be backwards compatible.
  var hardware = {};



  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/IOS-XR/Model", value:model);

  set_kb_item(name:"Host/Cisco/IOS-XR/Port", value:port);
  set_kb_item(name:"Host/Cisco/IOS-XR/Protocol", value:proto);

  type   = "router";
  source = "SNMP";

  var detection_type = 'remote';
  var confidence = 98;

  if (ssh)
  {
    source = "SSH";
    detection_type = 'local';
    confidence = 100;

    os = "Cisco IOS XR " + ver;
    set_kb_item(name:"Host/OS/CiscoShell", value:os);
    set_kb_item(name:"Host/OS/CiscoShell/Confidence", value:confidence);
    set_kb_item(name:"Host/OS/CiscoShell/Type", value:type);
  }

  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + ver;

  if (!isnull(model))
    report += '\n  Model   : ' + model;
  if (port)
    report += '\n  Port    : ' + port;

  serial_number = grab_serial_number(show_inventory:show_inventory);
  if(!empty_or_null(serial_number))
  {
    set_kb_item(name:"Host/Cisco/SerialNumber", value:serial_number);
    report += '\n  SN      : ' + serial_number;
    snc = new structured_data_asset_identifier();

    # report structured data value
    id_data = { 
      'identifier_source' : 'ciscoSerialNumber', 
      'identifier_value' : serial_number,
      'type' : 'Network Device Serial Identifier'
    };

    dbg::detailed_log(lvl:3,
      src:SCRIPT_NAME,
      msg:'id data found',
      msg_details: {
        "findings": { "lvl": 3, "value":id_data }
        }
    );

    snc.append('identifier', id_data);
    snc.report_internal();
  }

  report += '\n';

  var vendor = 'Cisco';
  var product = 'IOS XR';
  var os_name = strcat(vendor, ' ', product);

  var cpe = 'cpe:/o:cisco:ios_xr';

  register_os(
    type       : detection_type,
    method     : source,
    confidence : confidence,
    protocol   : proto,
    port       : port,

    vendor     : vendor,
    product    : product,
    version    : ver,
    os_name    : os_name,

    cpe : cpe
  );

  if (!empty_or_null(model))
  {
    # Normalize model

    # Convert hyphen to space (e.g. IOS-XRv => IOS XRv).
    if (model =~ '^IOS-')
      model = preg_replace(string:model, pattern:'^IOS-', replace:'IOS ');

    # Place a space between the model series and model number except for the CRS series.
    var models_pattern = 'IOS XRv|NCS|ASR';
    var pattern = strcat('^(', models_pattern, ')[ -]*([0-9].*)');

    var model_series, model_number;

    matches = pregmatch(string:model, pattern:pattern, icase:TRUE);
    if (!empty_or_null(matches))
    {
      model_series = matches[1]; # Examples: IOS XRv, NCR, ASR
      model_number = matches[2]; # Examples: 9000, 5500, 540L

      model = strcat(model_series, ' ', model_number);
    }

    # Remove extraneous data (e.g. 12816/PRP => 12816)
    var product_split = split(model, sep:'/', keep:FALSE);
    model = product_split[0];

    # Prepend 'XR ' if model is only numeric (e.g. 12416)
    if (model =~ '^[0-9]+$')
      model = 'XR ' + model;

    var full_name = strcat(vendor, ' ', model);
    cpe = 'cpe:/h:cisco:' + model;

    register_hardware(
      type        : detection_type,
      method      : source,
      confidence  : confidence,
      protocol    : proto,
      port        : port,

      category    : 'system',
      full_name   : full_name,
      vendor      : vendor,
      product     : model,

      serial_number : serial_number,

      cpe         : cpe
    );
  }

  security_report_v4(severity:SECURITY_NOTE, port:port, proto:proto, extra:report);

  exit(0);
}

var showver, desc, port;

# 1. SSH
showver = get_kb_item("Host/Cisco/show_ver");
if (showver)
  test(s:showver, ssh:TRUE, port:0);

# 2. SNMP
desc = get_kb_item("SNMP/sysDesc");
if (desc)
{
  port = get_kb_item("SNMP/port");
  if (!port) port = 161;

  test(s:desc, port:port, proto:'udp');
}

audit(AUDIT_UNKNOWN_DEVICE_VER, "Cisco IOS XR");
