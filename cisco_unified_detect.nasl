##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(70088);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_name(english:"Cisco Unified Communications Manager (CUCM) Web Detection");

  script_set_attribute(attribute:"synopsis", value:
"The web interface for Cisco Unified Communications Manager (CUCM) was detected.");
  script_set_attribute(attribute:"description", value:
"The web interface for Cisco Unified Communications Manager (CUCM) was detected.

Note: This plugin does not report anything. It only collects version information to be used downstream.");
  # https://www.cisco.com/c/en/us/products/unified-communications/unified-communications-manager-callmanager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cc20e40");
  # https://www.cisco.com/c/en/us/products/unified-communications/unified-presence/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6020006a");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports(443, 8443);
  exit(0);
}

include('http.inc');
include('ssl_funcs.inc');

var port = get_http_port(default:443);
var encaps = get_port_transport(port);
var transport;

if (empty_or_null(encaps) && encaps <= ENCAPS_IP)
  transport = ssl_transport(verify:FALSE);

var web_detect_path = '/cucm-uds/version';
var cucm_resp = http_send_recv3(
  method:'GET',
  port:port,
  item:web_detect_path,
  transport:transport,
  exit_on_fail:FALSE
);

if ('cucm-uds' >< cucm_resp[2])
{
  var version = pregmatch(string:cucm_resp[2], pattern:'<version>([^<]+)</version>');
  if (!empty_or_null(version))
  {
    replace_kb_item(name:'cisco_cucm/version', value:version[1]);
    replace_kb_item(name:'cisco_cucm/path', value:web_detect_path);
    replace_kb_item(name:'cisco_cucm/method', value:'Web UI');
  }
}
else
{
  audit(AUDIT_NOT_INST, 'Cisco Unified Communications Manager');
}
