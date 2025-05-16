#TRUSTED 6d37cce74a7acf00a3cada65a1abd96f1a1f5a9516ae7eb9a59bb789cc402402c270f729df564aa976f3456cb7a19c8ce16242b3bf0d9b6f821129356ef7d7293cca45bb50fcffab9a42cc2aadbe0207b540e718955955a1c228369e6487ed21b7bfed9e70d7b1f6a91baec9838ba3c21e782f3196548a4b0d05dc39cc108c39384323aa9807d2ce1b18785ccac2d481d8803f24b76bd8a58232e86c9862556529a793856aad92d3d62fd4a01095267fed4037565b1a354e42e5bf418eb5b62b5ee24d36bc2660fb45b82c3224da63b646dfa731cb1a3c5d8bb47d22c08077a0464933df48df81097531db6cf711983b36054c05300292c6e7c1e39af532a256f3bb6fb4bbdc305b245e8eb25f6ca20ed5014beccad09186c62218153f28f969109dad5c28ba3e9d023ba23fd5204c843194dbeb6f05676828cb9f907ddb179af4e6b39cdf62412462b24044b01885d6e8b2829825a369350c6e46ca833f489b6c43ca933be4234701b4c91fac891b00106d13908804d2259c72ec3e11ca8a22511c81b672152200cfd4e3f60cdf93ec25d505ddcbb4d24e93b91c1041d07d71d04588afac39bd0f0bef9fa3b858bdb0545c208c579b58ecc14b566b24acc51c1d959e7a67ae9181e5add114132ccc6c8a3dae7880cd34363a7527bddab66ddf3f3cd3469ef5e5839edc2f52976ca7962a08d0ffe45773ea4a4475242b512551
#TRUST-RSA-SHA256 71bf4fe018fb980c30ede0e40214032132ea4ad7cda6ae9e4bfceb7684924b85b2e9be4e4706e891241c4612b7852fedfb3150a7bc997da8aef81da15f1573c8d58ee310b6f9bb1f05a79fbd5bab4ecb4762e9e51cd51482c45bd536e341ddb8c9c73400b7ac724ecd92eb8638ca852a843e423d5bba557b8856b985a044bf75eb4c1381d7bdf4af0c231027e78e8ee46d9640e77b39269d99c613563283474041d293122ea87cb0d139b171b38f79b7d9b17ff63d9d26fc746edf51d63d7d65d66b0bfe357c72648fd5d5feafe9f4bff555301814516a7d2ec6010bfce83e673101b9ce95cc284e27f3d7be06a864ec3a3b8d39e4303abd2289f6364e0de298ba67af09caecc50b81f8367ef948878fed9267bc1281347acf91e17c41e52ad3df15e5b95dfe9aa23b0aa6d251fce67e207cfe4244dde25e578baad0a3743819b1b2c5637c4a19ac9f91de5db7c6e5cb5b566cd6cfbdef29d6e3351b999215e2642bb416334dc5cf65f938da73796337d3aef2edf81148472bb7a6b75f1cb249af5b1956e119b8639a75a63d6422b113ed4e398cf1b1f078e8b996858482d7cd1c553140ddfaac6686d90af30251bc782d4a04bb52b6161942a369156c9ce40d921839ed54ac50c14124bbd62250bfb9f5a5655dfed0f5f4dc5ab3f84a522ddf60b2c4bb4500c9e772c1458c51b2d9465a8634901e36b139bba5aaf686203a58
##
# (C) Tenable, Inc.
##

include("compat.inc");

if (description)
{
 script_id(55932);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_xref(name:"IAVT", value:"0001-T-0642");

 script_name(english:"Junos Version Detection");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the operating system version number of the
remote Juniper device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Junos, an operating system for Juniper
devices. 

It is possible to read the Junos version number by logging into the
device via SSH, using SNMP, or viewing the web interface.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Junos Local Security Checks");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "os_fingerprint.nasl", "netconf_detect.nbin");
 script_require_ports("Host/Juniper/show_ver", "SNMP/sysDesc", "Host/OS");

 exit(0);
}

include("snmp_func.inc");
include("http.inc");
include('host_os.inc');
include('hardware_registration.inc');
include('os_install.inc');
include('structured_data.inc');

##
# Saves the provided Junos version, build date, model,
# source, port and chassis serial number in the KB, 
# generates plugin output, registers os and exits.
#
# @param ver JUNOS version number
# @param build Juniper device type
# @param model Juniper model number
# @param source service used to obtain the version
# @param port Port used in detection (0 for SSH)
#
##
function junos_report_exit(ver, build, model, source, port, serial)
{
  var snj; # Serial Number Juniper
  var id_data, type, confidence;

  if (!empty_or_null(ver))
  {
    set_kb_item(name:"Host/Juniper/JUNOS/Version", value:ver);
    if (report_verbosity > 0)
      report += '\n  Junos version : ' + ver;
  }
  if (!empty_or_null(build))
  {
    set_kb_item(name:"Host/Juniper/JUNOS/BuildDate", value:build);
    if (report_verbosity > 0)
      report += '\n  Build date    : ' + build;
  }
  if (!empty_or_null(model))
  {
    set_kb_item(name:"Host/Juniper/model", value:model);
    if (report_verbosity > 0)
      report += '\n  Model         : ' + model;
  }
  if (!empty_or_null(port))
  {
    set_kb_item(name:"Host/Juniper/JUNOS/Port", value:port);
    if (report_verbosity > 0)
      report += '\n  Port          : ' + port;
  }
  if(!empty_or_null(serial))
  {
    set_kb_item(name:"Host/Juniper/JUNOS/Serial Number", value:serial);
    snj = new structured_data_asset_identifier();

    # report structured data value
    id_data = { 
      'identifier_source' : 'juniperSerialNumber', 
      'identifier_value' : serial,
      'type' : 'Network Device Serial Identifier'
    };

    dbg::detailed_log(lvl:3,
      src:SCRIPT_NAME,
      msg:'id data found',
      msg_details: {
        "findings": { "lvl": 3, "value":id_data }
        }
    );

    snj.append('identifier', id_data);
    snj.report_internal();

    if (report_verbosity > 0)
      report += '\n  Serial        : ' + serial;
  }

  ## set os identification
  if (!empty_or_null(source))
  {
    set_kb_item(name:"Host/Juniper/JUNOS/Source", value:source);
    if (report_verbosity > 0)
      report += '\n  Source        : ' + source;

    if (source == 'SSH')
    {
      if (!empty_or_null(ver))
        juniper_os += ver;

      type = 'local';
      confidence = 100;

      host_os_add(method: 'SSH', os: juniper_os, confidence: confidence, type: 'embedded');
    }

    if (source == 'SNMP')
    {
      if (!empty_or_null(ver))
        juniper_os += ver;
      
      type = 'remote';
      confidence = 85;

      host_os_add(method: 'SNMP', os: juniper_os, confidence: confidence, type: 'embedded');
    }

    if (source == 'NETCONF')
    {
      if (!empty_or_null(ver))
        juniper_os += ver;

      type = 'remote';
      confidence = 85;

      host_os_add(method: 'NETCONF', os: juniper_os, confidence: confidence, type: 'embedded');
    }

    if (source == 'HTTP')
    {
      if (!empty_or_null(ver))
        juniper_os += ver;

      type = 'remote';
      confidence = 85;

      host_os_add(method: 'WebUI', os: juniper_os, confidence: confidence, type: 'embedded');
    }

  }

  var vendor = 'Juniper';
  var product = 'Junos';
  var os_name = strcat(vendor, ' ', product);

  var cpe = 'cpe:/o:juniper:junos:';

  var display_version, version, update;

  # Parse out the 'release' as the 'update' to match CPEs
  #  - Examples:
  #   - 18.4R2-S9   => cpe:/o:juniper:junos:18.4:r2-s9
  #   - 15.1X53-D25 => cpe:/o:juniper:junos:15.1x53:d25
  var pattern = '^([0-9]+\\.[0-9X]+)-?([A-WYZ][A-Z0-9.-]+)';
  var matches = pregmatch(string:ver, pattern:pattern, icase:TRUE);
  if (!empty_or_null(matches))
  {
    display_version = matches[0];
    version         = matches[1];
    update          = matches[2];
  }

  register_os(
    type       : type,
    method     : source,
    confidence : confidence,
    port       : port,

    vendor          : vendor,
    product         : product,
    version         : version,
    display_version : display_version,
    update          : update,
    os_name         : os_name,

    cpe : cpe
  );

  if (!empty_or_null(model))
  {
    var full_name = strcat(vendor, ' ', model);
    cpe = 'cpe:/h:juniper:' + model;

    register_hardware(
      type        : type,
      method      : source,
      confidence  : confidence,
      port        : port,
    
      category    : 'system',
      full_name   : full_name,
      vendor      : vendor,
      product     : model,

      serial_number : serial,
    
      cpe         : cpe
    );
  }

  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);

  exit(0);
}

var juniper_os = 'Juniper Junos ';

# 1. SSH

var showver = get_kb_item("Host/Juniper/show_ver");
var register_junos_os = FALSE;

var model, junos, port, hardware_extensive, he_model, kernel, he_serial, serial,
report, desc, build, community, soc, device, ports, res, match;

if (showver)
{
  model = pregmatch(string:showver, pattern:'Model: +(.+)');
  junos = pregmatch(string:showver, pattern:'Junos: (.+)');
  port = 0; #SSH port is considered local

  hardware_extensive = get_kb_item("Host/Juniper/show_chassis_hardware_extensive");
  if (!empty_or_null(hardware_extensive))
  {
    he_model = pregmatch(string:hardware_extensive, pattern:'FRU Model Number: +(.+)');
    if (!empty_or_null(he_model) && !empty_or_null(he_model[1]))
      model = he_model;

    # Grab chassis serial number
    he_serial = pregmatch(string:hardware_extensive, pattern:"Chassis\s+([A-Za-z0-9]+)\s");
    if(!empty_or_null(he_serial) && !empty_or_null(he_serial[1]))
      serial = he_serial[1];

  }

  # Get approximate Date of Build from Junos build version
  # example: MGD release 16.2R2-S1 built by builder on 2017-08-25 04:07:53 UTC
  if (junos)
  {
    kernel = pregmatch(string:showver, pattern:'(' + junos[1] + ') .+on ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) .+');
  }
  # Get Date ond approximate version of Build
  # example: KERNEL 16.2R2-S1 built by builder on 2019-18-18 12:01:53 UTC
  else
  {
    kernel = pregmatch(string:showver, pattern:'KERNEL ([^ ]+) .+on ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])');
  }

  if (model && kernel)
  {
    set_kb_item(name:"Host/Juniper/kernel", value:kernel[0]);

    junos_report_exit(ver:kernel[1], build:kernel[2], model:toupper(model[1]), source:'SSH', port:0, serial:serial);
  }
}

# 2. SNMP

desc = get_kb_item("SNMP/sysDesc");

if (desc)
{
  junos = pregmatch(string:desc, pattern:"JUNOS ([0-9.]+[^ ]+)");
  build = pregmatch(string:desc, pattern:"Build date: ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])");

  # if the Junos version was obtained via SNMP, try to get the model as well
  if (junos && build)
  {
    community = get_kb_item_or_exit("SNMP/community");
    port = get_kb_item("SNMP/port");
    if(!port) port = 161;

    if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
    soc = open_sock_udp(port);
    if (!soc) exit (0, "Failed to open a socket on port "+port+".");
    device = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.2636.3.1.2.0");
    close(soc);

    if (device)
    {
      # e.g. Juniper J2350 Internet Router
      model = pregmatch(string:device, pattern:"^Juniper ([^ ]+)");
      if (empty_or_null(model) && empty_or_null(model[1]))
        model[1] = 'n/a';
    }

    junos_report_exit(ver:junos[1], build:build[1], model:toupper(model[1]), source:'SNMP', port:port);

  }
}

# 3. NETCONF

if (get_kb_item('Host/netconf/junos'))
{
  var netconf_port = get_kb_item('Host/netconf/port');

  # try and get hardware model and firmware version from 'show versions' output.
  var versions = get_kb_item('Host/netconf/junos/versions');
  if (!empty_or_null(versions))
  {
    var version_check = pregmatch(pattern:"JUNOS: ([A-Z0-9\.]+)(?:\sFLEX)?",string:toupper(versions));
    var model_check   = pregmatch(pattern:'MODEL: ([A-Z]+)',string:toupper(versions));

    if (empty_or_null(version_check) && empty_or_null(version_check[1]))
      version_check[1] = 'n/a';

    if (empty_or_null(model_check) && empty_or_null(model_check[1]))
      model_check[1] = 'n/a';

    junos_report_exit(ver:toupper(version_check[1]), model:toupper(model_check[1]), source:'NETCONF', port:netconf_port);
  }
}

# 4. Web (only older versions allow us to view the version w/o authenticating)
juniper_os = get_kb_item_or_exit('Host/OS');
if ('junos' >!< tolower(juniper_os)) exit(0, 'The host wasn\'t fingerprinted as Junos.');

ports = get_kb_list('Services/www');
if (isnull(ports)) exit(0, 'The "Services/www" KB item is missing.');

foreach port (ports)
{
  res = http_send_recv3(method:'GET', item:'/login', port:port, exit_on_fail:TRUE);
  match = pregmatch(string:res[2], pattern:'<div class="jweb-title uppercase">.* - ([^<]+)</div>');
  if (isnull(match)) continue;
  else model = toupper(match[1]);

  res = http_send_recv3(method:'GET', item:'/about', port:port, exit_on_fail:TRUE);
  match = pregmatch(string:res[2], pattern:'Version (.+) *built by [^ ]+ on ([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])');
  if (isnull(match)) exit(0, 'Unable to get Junos version from the web interface, authentication may be required.');

  junos = match[1];
  build = match[2];

  junos_report_exit(ver:junos, build:build, model:toupper(model), source:'HTTP', port:port);

}

exit(0, "The Junos version is not available.");
