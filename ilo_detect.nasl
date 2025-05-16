#TRUSTED 96ae10695b048178b867676f09c42a8bfd1efda6cd534137eca3afefa41a4cf1d752ba98691a5d7f34038bdfac3f4118b92c94dc672243533168fe6454b68daade3c30002f8edab5f586b4367d45d6e9801e1ab7b6eb92e98ddbb9fd5d42da3750acbd2d86055cb2ebe2e66451ea6c482f94e2c58e5f0e7c525ca5bcf2b5f1975e9e160febe008fc5d7fb08cef678ebf3262ad4248ae3dd632e4ae8a21a8c1a65407ef884381f29945cd20d848cf608fe7b28b59ebf7bd7b87a6eaa7cd0275075d3a9e166dfeb8ee1c763a3a32aa09cd680b116b735c32948f708c5ce88acef9c21424fa7bb097634828c03052ef93bb5339cfa0fc64097bf51956651662ec983756d4ff485f31a53157192ce98dc12941d53a33a2a8173388228c1a1954724f4c93d86efe5dcffe1702ae2c5a43d9e4b56f9c1ed45b773a5a3a488cc9b0ffd951c4f801e4edc33eb9086dbd945d83dd73183a6552ae5124fcffc77fc5ba7f2bd3655ab657d0d52eaa2ed4c0aac9cd2f4d1d742b0e0fb03733736c65de4dd72326b2cb76556051dfdbd73ca304d87c56cfee03a5516584dba2feae7aca301c1a7807c13fdf30be7d92041c44050237e4b1726a975b6c4071bdb867ab51b87b3406b175739452ab636b86ea4c9fd85dacf837e213df2b5c9cfcac863ae544b820a38d6d389ab71bc06328d4b1e4a0afcc12a0aaf678e5cc1ac2043eb21475cd28
#TRUST-RSA-SHA256 2332d408f5741c5650547cdd8db9684c12cd9c286ffd60e92a69ec4f7b47e9b382a5a97ca0a3b23bd8ed6eaab861c0501c9652b8c14db074e8e0e64a92052b3fc5658c0e5e3f8b9766723a0ebbdd2407c31fd99284484bb85e45cd63938716d7ed5aebabf4760a45cda0485655d91e1018a096f8e6390a62553ebadb77e2e6f2b10feed1bc5642c345be18fe67f7e53d888554633cf4c68e78b5939b807f5e3ff27e2163078651eb37d770d8480fa7dbd586381f32d74f4770a02ee46b9dcad5bac3810fbb11f816a3806785b2b5c6b5398ba65d5aa69a30d96e90753b3e3e3ea943db6d28932b03cc2cddd44ba8e05bd25aff82651511df6b336ec3578610fd9dd6c59cfb04fde17f35d65bdc9634be38482e1ba8331a27ee847d380fb7e4773bd8bfc4349f53986048c6851637f2e851dab9287af25ac6a2282cf45bff9d48e1fce582f2cca62bcd7da9932add8d2b70ee95e7a2e6ef9e22da4d1528c5686e8650d61641f53c940a52edb4cf9edfc7e111218a479d2f8255848ad6d59957c9b8cfa08a85eb6d0d903678a2793c5ee8bbe163951f64cb47cb53246095b7bfab7aa41233126392b7e5d7118839acea6768de3ff227ff07b7f713ba2a5bc56b19821e91ec93d8677915d5202fa10a6296619c1cfa49e557e30b1ff17033ea8361ba1c1a3a000a8d9b1b85734cbc3e299d16e67419b051df907bb26ece3d398434
#
# (C) Tenable Network Security, Inc.
#

# Modifications by Daniel Reich <me at danielreich dot com>
#
# - Added detection for HP Remote Insight ILO Edition II
# - Removed &copy; in original string, some versions flip the
#   order of Copyright and &copy;
# - Revision 1.2
#
# The above changes have since been removed.
# "HP Remote Insight ILO Edition II" mentioned above is a misspelling of
# "Remote Insight Light-Out Edition II" which is NOT iLO and is irrelevant.

include('compat.inc');

if (description)
{
  script_id(20285);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/14");

  script_name(english:"HP Integrated Lights-Out (iLO) Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is an HP Integrated Lights-Out (iLO) server.");
  script_set_attribute(attribute:"description", value:
"The remote host is an HP Integrated Lights-Out (iLO) server. These servers are embedded systems integrated into HP 
ProLiant servers for the purpose of out-of-band management.");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this host if you do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Service detection");

  script_require_ports("Services/www", 80, 443);
  script_dependencies("httpver.nasl", "broken_web_server.nasl");

  exit(0);
}

include('ilo_func.inc');

# Unfirewalled, there should be exactly 1 http & 1 https port.
# We retrieve a list and not branch because we are detecting whether or
# not the host server is iLO, not which ports are running the web interface.
var ports = get_kb_list("Services/www");

# By default, iLO listens on 80 and 443.
ports = add_port_in_list(list:ports, port:80);
ports = add_port_in_list(list:ports, port:443);

# Will track ports the interface is listening on.
# We may not have the firmware version until all ports are tried,
# so we delay calls to add_install.
var interface_ports = make_list();

var info = NULL;
foreach var port (ports)
{
  # If enabled, xmldata?item=all contains a superset of the data we could
  # retrieve by other means, so we try it first.
  var xml_info = detect_xmldata_all(port);

  # Not null signifies either that we were able to retrieve data or that
  # the remote host is iLO and the feature is disabled.
  if (!empty_or_null(xml_info))
    info = merge_hashes(info, xml_info);
  else # Now try /upnp/BasicDevice.xml
  {
    xml_info = detect_upnp_basic_device(port);
    if(!isnull(xml_info))
      info = merge_hashes(info, xml_info);
  }

  var more_info = NULL;
  if (isnull(info["generation"]))
  {
    if (is_ssl(port))
    {
      dbg::log(src:SCRIPT_NAME,msg:"XML not available. Trying via HTTPS");
      more_info = detect_https(port);
    }
    else
    {
      dbg::log(src:SCRIPT_NAME,msg:"XML not available. Trying via HTTP");
      more_info = detect_http(port);
    }

    info = merge_hashes(info, more_info);
  }

  if (!isnull(more_info) || !isnull(xml_info))
    interface_ports = make_list(interface_ports, port);
}

if (isnull(info))
  audit(AUDIT_NOT_DETECT, "HP Integrated Lights-Out");

# Backup method if XML does not identify Superdome.   
if (empty_or_null(info["server_model"]))
{
  var server_model, matches;
  var res = http_get_cache(port:port, item:"/");
    dbg::log(src:SCRIPT_NAME,msg:"cache output: " + obj_rep(info) + "\n");
  if ('HPE-iLO-Server' >< res)
  {
    matches = pregmatch(pattern:'[Ss]uperdome2', string:res, multiline:TRUE);
    if (!isnull(matches)) 
      info["server_model"] = matches[0];
  }
}

# This is a host OS detection
dbg::log(src:SCRIPT_NAME,msg:"info found: " + obj_rep(info) + "\n");
var extra = NULL;
if ( !empty_or_null(info["firmware"]) )
{
  extra["Version"] = info["firmware"];
}
host_os_add( method:"ilo_detect", os:"HP Integrated Lights-Out", confidence:95, type:"embedded", extra:extra );

# This information is about the host's firmware.
# Nothing is specific to the web interface,
# however info["firmware"] may be updated
# (and should be before the add_install() call)
foreach var key (make_list("generation", "firmware", "cardtype"))
{
  if (isnull(info[key]))
    continue;

  if (key == "firmware" && "F.0" >< info[key] && !isnull(info["cardtype"]) && info["cardtype"] == "Integrity")
  {
    set_kb_item(name:"ilo/firmware_full_version", value:info[key]);
    dbg::log(src:SCRIPT_NAME,msg:"Removing 'F.0' from firmware version " + info[key] + " due to detection of Integrity cardtype");
    info[key] = str_replace(string:info[key], find:'F.0', replace:'');
  }

  set_kb_item(name:"ilo/" + key, value:info[key]);
}

# Now that we have exhaustively attempted to find the firmware
# we record the existence of the web interface.
foreach port (interface_ports)
{
  replace_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

  # There can only be one version and instance of the web app, though
  # it may listen on multiple ports (max 1 http and 1 https). All settings
  # are the same across those ports.
  add_install(
    appname : "ilo",
    dir     : "/",
    port    : port,
    ver     : info["firmware"],
    cpe     : "cpe:/o:hp:integrated_lights-out"
  );

  if (info["sso"])
    set_kb_item(name:"www/ilo/" + port + "/sso_enabled", value:info["sso"]);
}

var is_moonshot = is_moonshot_device(ports:interface_ports);
if(is_moonshot)
  replace_kb_item(name:'www/ilo/moonshot', value:1);

var report = NULL;
if (report_verbosity && max_index(keys(info)) > 0)
{
  report = '\nHP Integrated Lights-Out (iLO)\n';

  if (!isnull(info["generation"]))
    report += '\n  Generation       : ' + info["generation"];

  if (!isnull(info["firmware"]))
    report += '\n  Firmware Version : ' + info["firmware"];

  if (!isnull(info["sso"]))
  {
    if (info["sso"])
      report += '\n  Single Sign-On   : Enabled';
    else
      report += '\n  Single Sign-On   : Disabled';
  }

  if (!isnull(info["server_model"]))
  {
    report += '\n\nAssociated ProLiant Server\n';
    report += '\n  Model : ' + info["server_model"];
    replace_kb_item(name:'www/ilo/server_model', value:info['server_model']);    
  }

  if(is_moonshot)
    report += '\n\nChassis : Moonshot iLO';
  report += '\n';
}

security_note(port:0, extra:report);
