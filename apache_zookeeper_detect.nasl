#TRUSTED a84c633559e6bd48c20260ed75c408cfd40cd6301407678bf0b4e8f0be7621c3e52181e5758f8521eecf5fa78f0ccf17112f029481bfec6489ff8b253e613892aed67a4af73fee53dfd01e5bc39269e414ac3551ec9bb672dd4dfa0a7fcc5ed72fa1c64579eacf1707a6fce61ea9ce0d5ebf1039be144cc0e66fe7012ea06938a9965f06d4bfa8ec773ef3978ededd9135840d31b6d079935381a97ba8aa83f3fb48483dbc40ae2188e33c0bd848e9f5dab8cf0a5163ce992bdcc7e93a23ad4105d4c8b23a3b74cb4c1ee89d979a55fda4bc07d45b753f385266e4d0df9a1b30077a0d8720ab3a5a0368474658761bea9a93f74188e0155a2d87b876b71b68fd704be39066d7ada1bd9f3503caa8a19ff2e557111d2627851603bc5083954e34c38faf7a728b5312828b9e61d41a6ccecd7c97ca621aa0415c15d06b61e8b353c101c273fdb935cbca41d68ff84660678b4767cae980492d41b277b4ef57d8aedb1d2540df5e954b8df37ecd7a3309f8270bda229062c69c719468ca8fd9a418f84681a749dc89b1cc20a0dd918dcbcabebbaf88da0caf535fcf13591d1e1d07ad0ce82da639700d70b494764c74b315371a4c4e628e543fcf6e51584784cc8dc6aeb802a68218de854033d8143dbe835ea8092b982853a4251e06673d01d8ad6d34c8ac6ef76d303deaee487046ba9a2dee937b894b2c62e6c5966fe43297d1
#TRUST-RSA-SHA256 44b807159cbb094a60a555f9e2fc85b0cb8da715457fe52683d387cd4b91ce46e329a3b1801769c2375fe818f0911e0fe6c80a7d13e1d5740706320f1c29e6b08869b8b607bc84f6805f3b987a94a30b237271445d30945110437b55cfd121efcdf734ebe195606ad0aee07955afa69e94e11e186b9da46b6570c39496fd6919dae319e842ff21468601ef54c0dc6a42d1a9289da8f8bfcc7794452cbcff414c5264587f8c5ba405e2d2c7046a9d3d880a220230d00eae89708ab5eed532dce64c63b366a6e6982e72252d4ff1303560e32a8b5957b5c45cef45cb1e1a257b40c06d5499d7663a72795915a3b47b86f28d07bd9d4f68c460bd9418f9e930f637b9b765f6e2241a852aa181a24dc6cca92c2eee519f10b42422d53221d6b5998e8189a0cdfad4e0e612928737964cf06634148520c5e17ed4badbb97d3b9d978f361161d13e0c300a396a763a245a1fff7b77b3706090e7ea534fad5807cffaa2aae7bc2856dac8d45bad0d6f342fd9feebe0602521548705d6ab18c753b9e63409c36331209b4fc1f14cb46db337e0c6ba2570f6e262ea088826f3630cb94a5456586249c149940c867ab20c250cef24aaf5e7e7383b79211b1d04998f9472a2ee0c349febdef45be78882af23a6c9b117d435278fb72fb6a3f47a490b52bcec16bacdcc13ad4722f495a27732abb5318b05762f0305e9746f290fcd84659460
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110267);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");
  script_xref(name:"IAVT", value:"0001-T-0536");

  script_name(english:"Apache Zookeeper Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"An Apache Zookeeper server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an Apache Zookeeper server.");
  script_set_attribute(attribute:"see_also", value:"https://zookeeper.apache.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:zookeeper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl", "process_on_port.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/unknown", 2181);

  exit(0);
}

include('ssh_func.inc');
include('telnet_func.inc');
include('lists.inc');
include('install_func.inc');
include('debug.inc');
include('local_detection_nix.inc');

service_name = "Apache Zookeeper";
protocol = "zookeeper";

ports = make_list(2181);

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  additional_ports = get_kb_list("Services/unknown");
  if (!isnull(additional_ports))
    ports = make_list(ports, additional_ports);
}

ports = list_uniq(ports);
port = branch(ports);

if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

if (get_kb_item('debug_TESTING') == 1)
  response = 'Zookeeper version: 3.1.0,';
else
{
  socket = open_sock_tcp(port);
  if (!socket)
    audit(AUDIT_SOCK_FAIL, port);

  send(socket:socket, data:"stat");
  response = recv(socket:socket, length:2048);
  close(socket);
}
if (empty_or_null(response))
  audit(AUDIT_NOT_DETECT, service_name, port);

match = pregmatch(pattern:"Zookeeper version: ([0-9.]+)[-,]", string:response);
if (empty_or_null(match) || empty_or_null(match[1]))
  audit(AUDIT_NOT_DETECT, service_name, port);

dbg::log(msg:'stat match: ' + obj_rep(match));

version = match[1];

register_service(port:port, ipproto:"tcp", proto:"zookeeper");
replace_kb_item(name:"zookeeper/" + port + "/version", value:version);

enable_ssh_wrappers();

uname = get_kb_item("Host/uname");
proto = get_kb_item("HostLevelChecks/proto");
cmdline = base64_decode(str:get_kb_item("Host/Listeners/tcp/"+port+"/cmdline"));

if (('Linux' >< uname || 'AIX' >< uname) && proto && cmdline)
{
  dbg::log(msg:'Going to try to open ssh connection on port: ' + port);
  if (proto == 'local')
  {
    info_t = INFO_LOCAL;
  }
  else if (proto == 'ssh')
  {
    sock_g = ssh_open_connection();
    if (sock_g) info_t = INFO_SSH;
  }
  if (info_t)
  {
    dbg::log(msg:'ssh connection opened on port: ' + port);
    dbg::log(msg:'cmdline: ' + cmdline);
    match = pregmatch(pattern:"(?<=-cp\x00)([^\x00]+)", string:cmdline);
    if(match && match[1])
    {
      class_paths = split(match[1], sep:':', keep:FALSE);
      dbg::log(msg:'class_paths: ' + obj_rep(class_paths));
      match = collib::filter(f:function ()
          {return _FCT_ANON_ARGS[0] =~ "/.*?zookeeper[^/]*\.jar$";}, class_paths);
      dbg::log(msg:'match after filter: ' + obj_rep(match));
      if (match && max_index(match) == 1)
      {
        jar_path = dirname(match[0]);
        dbg::log(msg:'jar_path: ' + obj_rep(jar_path));
        template = 'cd \"$1$\" && pwd';
        res = ldnix::run_cmd_template_wrapper(template:template, args:[jar_path]);
        dbg::log(msg:'res: ' + obj_rep(res));
        if (res)
          jar_path = res;
      }
    }
    conf_path = pregmatch(pattern:"([^\x00]+?zoo\.cfg)",string:cmdline);
    if (conf_path && conf_path[1])
    {
      dbg::log(msg:'conf_path: ' + obj_rep(conf_path));
      template = 'cat \"$1$\"';
      res = ldnix::run_cmd_template_wrapper(template:template, args:[conf_path[1]]);
    }
    dbg::log(msg:'res from conf_path: ' + obj_rep(res));
    if (res)
    {
      match = pregmatch(pattern:"(?m)^\s*?clientPort=([0-9]+)", string:res, icase:TRUE);
      if (match && match[1] && match[1] == port)
      {
        dbg::log(msg:'match of clientPort: ' + obj_rep(match));
        config = res;
      }
    }
  }

  if (sock_g)
    ssh_close_connection();
}

if (jar_path && config)
{
  register_install(
    vendor:"Apache",
    product:"Zookeeper",
    app_name:service_name,
    port:port,
    path:jar_path,
    version:version,
    extra_no_report:{'config': config},
    cpe: "cpe:/a:apache:zookeeper"
  );
  report_installs(app_name:service_name);
}
else
{
  info = '\n  Version : ' + version + '\n';
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:info);
}
