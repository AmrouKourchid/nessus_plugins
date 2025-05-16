#TRUSTED 25ba47cbde320834e972a7e07cf7f0917a789d378cc8224aab7c8f106c274b65389afe835f914f7155022b535e95233ef5fa6ab941ef6592415e2cf6f5ccfd1b4ab72d85e4812c9a52f21684ffeb0bfe403a52e6d4c006f3853a7cf69f60287a43ff58a3813c856a6767efc8f0e476bd8434ca666990e93effe492a6076095faa7c4efd802010203c9db3932186399ca733141d9aea42d705b035c767a805cb7794f97013f0df1186e12f2b4f49602a4812ac2d36f43245582656f23079a815fc1e12f92b96f291a63f3dac3d137ea82ccb9e7a3b4293180b7883ed72668cb15cdbcba44912503b1c239fb925e2016f468cd7a8943a48b8ec6009f53938f767061252f5c6e8d7994b5830959bd0a911b1c65f4df69ed22ef081d7debe8b19d4596fb9f63a2574741329b18c6235e0630cedca2f88d49809a6e569da3142694a2f23a1323e66ee14feb33cdf4686368ea1fe662fdb367ed58f20906066b350895730eacdb86325936356b479aa3694ae6c399be57a70b0ed9e43d5c6770804402c2230530df993d89fdb836d512e29e7b812c55ed1ac0b88732e07c80c4d9e498a5bdeedc363d50ecc9d04bdb48bc6ff1a0152dacdab5559f467fad43ff9ec5b3ec5fb58fd6b1e4135b30ab1bace419e3db575eb34f0d13cdee9ab7aed8d818540166cecdcd9b40662db24b80a507cce93389c472ea5808e901235b526786f7e8
#TRUST-RSA-SHA256 6949ab1584d603fe06d506d656fbcec4538cb64e3a07fe8df49362b0bffdc29bb2045775b43df015b0ac1ac56523060365f658492b112b9d3f9e65ceb71439fad20d8dee98399d0715a821dfdb8b08d02b65027534799a45225669730edb8168f8b387030f2d2724924086d5fbe4374c457ef2636d80eda5bb9a459bab1926481b926319ac6c37f12e05f9a1ad276e4987028e3de5a0d088f5d6e6ad2ce726c29ba50620402f29860065ae2ca2a16978cba3998baa02f073122bcc969f6835e86fc151ee6383c178a946b9bf644561eeb7965098ff611a9048d7c4e1773d6fb1db1de2ea381491953ca25f2deb19e5ee6a2c0f4336d7f1186718c6067b9872ae69510ae5e4ad22b619b3867ee94cdd2c51f3a0f26d867f2749c3c8fe0469121a62e1e4736d99db1bc89c449e10b958fc817f695d6472f96c87d7dfe54d499dd8aa55b2caefc52e30481f613fa4f00c17b668746cececc857ccfc8cd912d5c5695b54a6777d17fe68dbb60ac428673300235a24441f8d1a75cb634c821fe8c2acfa9ac5766514098a245acf3d7718424ffead02f3f21579a46720d050f2be43804b3dd6b33e06e4f9c20fe1e2c266dd3fa03ab809ff3925049f460496648c39925ae14291b24a6298075db8ecfd5703e4922afc1920e445123615449ca142f0fa1d87a0effb4297973cb198af160611f569586b72910ab7d47a6faa033a72ff57
#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
 script_id(66696);
 script_version("1.26");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/18");

  script_xref(name:"IAVT", value:"0001-T-0555");

 script_name(english:"Cisco NX-OS Version");

 script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the NX-OS version of the remote Cisco device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running NX-OS, an operating system for Cisco
switches.

It is possible to read the NX-OS version and Model either through SNMP
or by connecting to the switch using SSH.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/30");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"CISCO");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc", "Host/aci/system/firmware/summary", "Host/Cisco/apic/show_version");
 exit(0);
}

include('hardware_registration.inc');
include('os_install.inc');
include("snmp_func.inc");
include("ssh_lib.inc");
include('structured_data.inc');

##
# Finds and returns chassis serial number in the 'show inventory' command output retrieved from the KB.
# @param [show_inventory:string] Output of 'show inventory' NXOS command, retrieved from the KB.
# @return [string|NULL] string containing the serial number if found, NULL if SN is not found or show_inventory is missing.
function grab_serial_number(show_inventory)
{
  if(empty_or_null(show_inventory)) return NULL;

  var sn_regex = 'NAME: "Chassis"(?:.|\\s)*?SN: (\\S+)';
  var serial_number = pregmatch(string:show_inventory, pattern:sn_regex, multiline:TRUE);

  if(!empty_or_null(serial_number)) serial_number = serial_number[1];
  else serial_number = NULL;
  
  return serial_number; 
}

##
# Saves the provided NXOS version number in the KB, generates plugin output,
# and exits.  If a model number is provided it is also saved in
# the KB and reported, but a model number is not required.
#
# @param ver NXOS version number
# @param device NXOS device type
# @param model NXOS model number
# @param source service used to obtain the version
# @param port Port used in detection (0 for SSH)
# @param proto Protocol used in detection (udp or tcp)
# @param sn Serial number of the device
#
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, device, model, source, port, proto, sn)
{
  local_var report, os;

  if (isnull(proto)) proto = 'tcp';

  set_kb_item(name:"Host/Cisco/NX-OS/Device", value:device);

  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/NX-OS/Model", value:model);

  set_kb_item(name:"Host/Cisco/NX-OS/Version", value:ver);
  set_kb_item(name:"Host/Cisco/NX-OS/Port", value:port);
  set_kb_item(name:"Host/Cisco/NX-OS/Protocol", value:proto);

  replace_kb_item(name:"Host/Cisco/NX-OS", value:TRUE);

  var type, confidence;

  if ( source == "SSH" )
  {
    type = 'local';
    port = 0;
    confidence = 100;

    os = "CISCO NX-OS " + ver;
    set_kb_item(name:"Host/OS/CiscoShell", value:os);
    set_kb_item(name:"Host/OS/CiscoShell/Confidence", value:confidence);
    set_kb_item(name:"Host/OS/CiscoShell/Type", value:"switch");
  }

  if ( source == 'SNMP' )
  {
    type = 'remote';
    confidence = 95;
  }

  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + ver;
  if (!isnull(device))
    report += '\n  Device  : ' + device;
  if (!isnull(model))
    report += '\n  Model   : ' + model;
  if (port)
    report += '\n  Port    : ' + port;
  if (sn)
    report += '\n  SN      : ' + sn;

  report += '\n';

  var vendor = 'Cisco';
  var product = 'NX-OS';
  var os_name = strcat(vendor, ' ', product);

  var cpe = 'cpe:/o:cisco:nx-os';

  register_os(
    type       : type,
    method     : source,
    confidence : confidence,
    port       : port,

    vendor     : vendor,
    product    : product,
    version    : ver,
    os_name    : os_name,

    cpe : cpe
  );

  if (!empty_or_null(device))
  {
    # CPE examples:
    #  - cpe:/h:cisco:nexus_2148t
    #  - cpe:/h:cisco:mds_9000:-
    #  - cpe:/h:cisco:ucs_6324_fabric_interconnect:-
    #  - cpe:/h:cisco:application_policy_infrastructure_controller:-

    product = device - 'Cisco ';

    var full_name = strcat(vendor, ' ', product);

    if (!empty_or_null(model) && model != 'Cisco APIC')
    {
      full_name += ' ' + model;

      if (product == 'UCS Fabric Interconnect')
        product = strcat('UCS ', model, ' Fabric Interconnect');
      else
        product += ' ' + model;
    }

    cpe = 'cpe:/h:cisco:' + product;

    register_hardware(
      type        : type,
      method      : source,
      confidence  : confidence,
      port        : port,

      category    : 'system',
      full_name   : full_name,
      vendor      : vendor,
      product     : product,

      serial_number : sn,

      cpe         : cpe
    );
  }


  security_report_v4(severity:SECURITY_NOTE, port:port, proto:proto, extra:report);

  exit(0);
}

var version = NULL;
var device = NULL;
var model = NULL;

var ips_ssh, ssh_port, banner, pat, ips_snmp, community, port, soc, txt, ips_aci, model_kb, ips_apic, failed_methods, show_inventory;
var serial_number, report, snc, id_data;

# 1. SSH
ips_ssh = get_kb_item("Host/Cisco/show_ver");
if (ips_ssh)
{
  show_inventory = get_kb_item("Host/Cisco/Config/show_inventory");
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

  if ("Cisco Nexus Operating System (NX-OS) Software" >< ips_ssh)
  {
    version = pregmatch(string:ips_ssh, pattern:"NXOS:\s+version\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*", icase:TRUE);
    if (isnull(version))
      version = pregmatch(string:ips_ssh, pattern:"[Ss]ystem:?\s+[Vv]ersion:?\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*");

    if (!isnull(version))
    {
      # Check if it's a UCS device
      # this can be expanded when we know more about Cisco UCS products
      ssh_port = get_service(svc:'ssh', default:22);
      banner = get_kb_item('SSH/textbanner/'+ssh_port);
      # e.g. textbanner = Cisco UCS 6200 Series Fabric Interconnect\n 
      if (!isnull(banner))
      {
        banner = chomp(banner);
        pat = "^Cisco UCS (\S+ Series) Fabric Interconnect$";
        model = pregmatch(string:banner, pattern:pat, icase:TRUE);
        if (!isnull(model)) device = 'Cisco UCS Fabric Interconnect';
      }

      if (isnull(model))
      {
        if ('MDS' >< ips_ssh)
        {
          device = 'MDS';

          model = pregmatch(string:ips_ssh, pattern:"MDS\s*\d+\s+[cC]([^\r\n\s]+)[^\r\n]*\s+Chassis");
          if (isnull(model))
            model = pregmatch(string:ips_ssh, pattern:"MDS\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");
        }
        else
        {
          device = 'Nexus';

          model = pregmatch(string:ips_ssh, pattern:"[Nn]exus\s*\d+\s+[cC]([^\r\n\s]+)[^\r\n]*\s+[Cc]hassis");
          if (isnull(model))
            model = pregmatch(string:ips_ssh, pattern:"[Nn]exus\s*([^\r\n\s]+)[^\r\n]*\s+[Cc]hassis");
          if (isnull(model))
          model = pregmatch(string:ips_ssh, pattern:"Hardware\r?\n\s*[Cc]isco (?:[Nn]exus )?\s*([^\r\n\s]+)\s+([Cc]hassis|\(.[Ss]upervisor.\))");
        }
      }

      if (!isnull(model))
        model = model[1];

      report_and_exit(ver:version[1], device:device,  model:model, source:'SSH', port:0, sn:serial_number);

    }
  }
  else if ("Device Connector Version:" >< ips_ssh &&
           "Management Package Version:" >< ips_ssh)
  {
    # Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucsfi-imm-syn-p6kZTDQC

    version = pregmatch(string:ips_ssh, pattern:"Device Connector Version\:\s(\d+)\.(\d+)\.(\d+)\-(\d+)");
    var imm_version = pregmatch(string:ips_ssh, pattern:"Management Package Version\:\s(\d+)\.(\d+)\.(\d+)\-(\d+)");

    if (!empty_or_null(version))
      version = strcat(version[1], '.', version[2], '.', version[3], '-', version[4]);

    if (!empty_or_null(imm_version))
    {
      imm_version = strcat(imm_version[1], '.', imm_version[2], '.', imm_version[3], '-', imm_version[4]);
      set_kb_item(name:"Host/Cisco/NX-OS/IMM_Version", value:imm_version);
    }

    if (!empty_or_null(version) &&
        !empty_or_null(imm_version))
    {
      device = 'Cisco UCS Fabric Interconnect';
      # Improving 'model' will require a scan of an actual UCS system, needed from field.
      model = '6400/6500';
      report_and_exit(ver:version, device:device,  model:model, source:'SSH', port:0, sn:serial_number);
    }
  }
}

# 2. SNMP
ips_snmp = get_kb_item("SNMP/sysDesc");
if (ips_snmp)
{
  community = get_kb_item("SNMP/community");
  if ( (community) && (!model) )
  {
    port = get_kb_item("SNMP/port");
    if(!port)port = 161;
    if (! get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

    soc = open_sock_udp(port);
    if (soc)
    {
      txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0");
      if ( (txt) && ('NX-OS' >< txt) )
      {
        # get version
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.9.22");
        if (txt) version = txt;

        # get model
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.2.149");
        if (txt && 'MDS' >< txt)
        {
          device = 'MDS';

          model = pregmatch(string:txt, pattern:"MDS\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");
        }
        if (txt && 'Nexus' >< txt)
        {
          device = 'Nexus';

          model = pregmatch(string:txt, pattern:"Nexus\s*([^\r\n\s]+)[^\r\n]*\s+Chassis");

        }
      }
    }
  }

  if (!isnull(model))
    model = model[1];

  if (!isnull(version))
    report_and_exit(ver:version, device:device, model:model, source:'SNMP', port:port, proto:'udp', sn:serial_number);
}

# 3. SSH (Nexus 9xxx Switches may support "ACI" (bash shell)
#          which also allows us to obtain version information)
ips_aci = get_kb_item("Host/aci/system/firmware/summary");
if (ips_aci)
{
  # Same expected format as with SSH above
  version = pregmatch(string:ips_aci, pattern:"[Dd]escription\s+:\s[Vv]ersion\s([0-9a-zA-Z\.\(\)]+)\s");

  if (!empty_or_null(version) && !empty_or_null(version[1]))
  {
    version = version[1];
    device = 'Nexus';

    model_kb = get_kb_item("Host/aci/system/chassis/summary");
    model = pregmatch(string:model_kb, pattern:"[Nn]exus\s*\d+\s+[cC]([^\s]+)[^\r\n]*\s+[Cc]hassis");
    if (isnull(model))
    {
      model = pregmatch(string:model_kb, pattern:"[Nn]exus\s*([^\s]+)[^\r\n]*\s+[Cc]hassis");
    }
    if (!empty_or_null(model) && !empty_or_null(model[1]))
      model = model[1];

    report_and_exit(ver:version, device:device,  model:model, source:'SSH', port:0, sn:serial_number);
  }
}

# 4. SSH (Nexus APIC Controller may support "ACI" (bash shell)
#          which also allows us to obtain version information)
ips_apic = get_kb_item("Host/Cisco/apic/show_version");
if (ips_apic)
{
  version = pregmatch(string:ips_apic, pattern:"\s([\d]+\.[\d]+\(.+\))");
  if (!empty_or_null(version) && !empty_or_null(version[1]))
  {
    version = version[1];
    device = 'Cisco Application Policy Infrastructure Controller';
    model = 'Cisco APIC';

    report_and_exit(ver:version, device:device, model:model, source:'SSH', port:0);
  }
}


failed_methods = make_list();
if (ips_ssh)
  failed_methods = make_list(failed_methods, 'SSH');
if (ips_snmp)
  failed_methods = make_list(failed_methods, 'SNMP');
if (ips_aci)
  failed_methods = make_list(failed_methods, 'SSH (ACI feature)');
if (ips_apic)
  failed_methods = make_list(failed_methods, 'SSH (ACI on APIC)');

if (max_index(failed_methods) > 0)
  exit(1, 'Unable to determine Cisco NX-OS version number obtained via ' + join(failed_methods, sep:'/') + '.');
else
  exit(0, 'The Cisco NX-OS version is not available (the remote host may not be Cisco NXOS).');
