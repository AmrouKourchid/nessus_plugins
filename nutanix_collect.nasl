#TRUSTED 9cf9d67b9c4ef289bcbff4c92b021523b70e25ec952cadf07ef440466ddd54931838de0ee432235eb83e9df750c36fe44002748a9748ff170c77bf113587a30d8ae94cf91a49f28b596682ae597ded653e4d5eb2b4babb5e8027242e093f9c9151dce8558102b97eb1e0e3399e47ca39bbfc15372293df5179a1cad2d8144aa46b78f4a1daa03fae219097a6ce03890833ab4a181e2d6af82dd5ad59e4189be0b1f3bc6c486fe1c32995c7f427a5d7c533fbaafc607e6f3717307b4353836a3cd1fa499fb0d64f49f2b3647d744638255f6106ba15669d0a3e6a07aa46ead9540cb26df33b41b12fea61994131e2ec9393c47bc42742968f34e780aa42a14fc8057e8d04e787b75d7c614c9397ddd0bbb2f05e04371e49fd94a8153990e1caa35428e0daff34544e950a3bf7bdc77fb536aaea52c181e2d83ee5b60efc12302870ec6e4f784917f71954bde9b6bc3cef29d1d8ad0119a96df57469a2e75ad6172a98dc17f501a1fa2784b657d1451212c5bad63a9f21f554349dc9e2923225786fde758eab54a9f29cf164bdc12f60169958b55034ceb7375ff7cbdd281297aa504196b35bb10f986216add7590e588bd4fbbd07fdc0e392200505471f2896320b5c858049c447e274ed7079476c3f1a95bfeb7f2da440ba9c5d47c378bbf4d9b0451a9c50a55377c75df2e9cb1c3b10b910553f2ed195f20c4d592ae69c3b88
#TRUST-RSA-SHA256 aed88b806bf39787153bdc37281248836bfac4d6ceb37af3a8ea97942f9af6ec2060a4078a86054b97ecd36d9d29d81e3050f9af243df322bef804aee31ba4203d9c282ba77a0570badd45d4ad46f7da555900ebaaf97b93637bebe8bc55b87c616341f9e821dfc7c85d9767ee8aea03b6154e31e39b35c4567b66d28aa95c43cb100f439649efe2eee70c03b104d545fd39a50eb73de976bf1cd34ee8d29fbbd1778de6ff31cfe5f9331f826589ec6756aa95e551452e8adc60b6d80399c9dd67d377c6601d5e3121f0ea594278ef0c3767a83592bea93086575926c4a6c53864a13a1642bba3a2ae9c2b93657e341fe40af4ea1d146dbcd1bd2457968b22ebb397bc516ad6c41c0d547efd3b6b1c35f06dbe044cc2270dda6ab313fc93be0b8ffd8ea1d1edb1ecaf9bc0d98124bc285ce76a6c32883bbcb7a3495f806bc860bc800942fc225d91ade8735440c92a6cfe1903acc1e25c889b654b1d2777e1ca01c1858e54654ad41c8ec43d1a982195bfeee92b17316dd8dba9d09b7552449ff3ae41d4294415c9db693eeff8c4cbfedd7034cede5be0a0b92ad7add95c6f33cb6b024d667f2b6be7a157639dbff3d6cba5d75050d82a1b8a6c1cb9d55d08bbc436fd09255224680c569aaa9556a16c111e23947d22f6b5efec553e29866f81cdc2ae5a0f364cc697967a8e7cc3415b302d052ba8fc1dc9d2451e138bdcaf25
###
# (C) Tenable Network Security, Inc.
#
###

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(160185);
  script_version("1.12");
  
  script_name(english:"Nutanix Data Collection");
  script_summary(english:"Collects Nutanix data.");

  script_set_attribute(attribute:"synopsis", value:"Collects all data from Nutanix PC using REST APIs.");
  script_set_attribute(attribute:"description", value:"Collects Nutanix data using REST APIs.");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/07");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:nutanix:pc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Misc.");

  script_dependencies("nutanix_settings.nasl");

  script_require_keys("Host/Nutanix/config/host", 
                      "Host/Nutanix/config/port", 
                      "Host/Nutanix/config/ssl", 
                      "Host/Nutanix/config/ssl_verify", 
                      "Secret/Nutanix/config/username", 
                      "Secret/Nutanix/config/password");

  script_timeout(0);

  exit(0);
}

if (!defined_func("inject_host") && defined_func("nasl_level") && nasl_level() <= 190200)
{
  exit(0, "Nessus older than 10.2");
}

include("compat_shared.inc");
include("http.inc");
include("nutanix.inc");
include("ssl_funcs.inc");
include("spad_log_func.inc");

if (defined_func("set_mem_limits")) 
{
  set_mem_limits(max_alloc_size:1024*1024*1024, max_program_size:1024*1024*1024);
}

##
# Wrapper for the collection and injection process.
##
function collect_nutanix_data()
{
  var config = nutanix::init();
  var hosts_to_inject = {};
  var nutanix_collection_host = get_host_ip();

  set_global_kb_item(name:"Nutanix/DataCollection/CollectionIP", value:nutanix_collection_host);

  # Optional Host Discovery
  if (config.auto_discovery_hosts)
  {
    nutanix::log(msg: '\n\nCollecting Hosts...\n', lvl:2, config:config);
    var host_list = nutanix::host_list(config:config);

    nutanix::log(msg: '\n\nEnumerating Hosts for Injection...\n', lvl:2, config:config);
    foreach (var host in keys(host_list))
    {
        set_global_kb_item(name:"Nutanix/Hosts/" + host, value:host_list[host]);

        nutanix::log(msg:"Discovered Nutanix Hypervisor: " + host + '\n', lvl:3, config:config);

        hosts_to_inject[host] = "Hypervisor";
    }
  }

  # Optional VM Discovery
  if (config.auto_discovery_vms)
  {
    nutanix::log(msg: '\n\nCollecting Virtual Machines...\n', lvl:2, config:config);
    var vm_list = nutanix::vm_list(config:config);

    nutanix::log(msg: '\n\nEnumerating Virtual Machines for Injection...\n', lvl:2, config:config);
    foreach (var vm in keys(vm_list))
    {
        foreach var ip (vm_list[vm])
        {
          nutanix::log(msg:"Discovered Nutanix VM: " + ip + '\n', lvl:3, config:config);

          hosts_to_inject[ip] = "VM";
        }
    }
  }

  nutanix::log(msg: '\n\nCollecting Cluster Info...\n', lvl:2, config:config);
  var cluster_info = nutanix::cluster(config:config);

  var cluster_count = 0;
  var cluster_skip_count = 0;

  foreach var cluster (cluster_info)
  {
    if (!empty_or_null(cluster.cluster_ip))
    {
      var ip_address = cluster.cluster_ip;
      var version = cluster.build.version;
      var full_version = cluster.build.full_version;
      var lts = cluster.build.is_long_term_support;
      var arch = cluster.cluster_arch;
      var service = cluster.cluster_service;
      var nodes = cluster.nodes;
      var software_map = cluster.software_map;

      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/ip", value:ip_address);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/version", value:version);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/full_version", value:full_version);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/lts", value:lts);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/arch", value:arch);
      set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/service", value:service); 

      nutanix::log(msg:"Discovered Cluster IP: " + ip_address + '\n', lvl:2, config:config);
      nutanix::log(msg:"Discovered Cluster Version: " + version + '\n', lvl:3, config:config);

      nutanix::log(msg:"Discovered Cluster IP to Inject: " + ip_address + '\n', lvl:3, config:config);
      hosts_to_inject[ip_address] = "Cluster";

      nutanix::log(msg: '\nProcessing Cluster Software Map...\n', lvl:2, config:config);
      foreach var software (software_map)
      {
        var software_version = software.version;

        if (!empty_or_null(software_version))
        {
          var software_type = software.software_type;
          var software_status = software.status;

          set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/" + software_type + "/software_type", value:software_type);
          set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/" + software_type + "/software_version", value:software_version);
          set_global_kb_item(name:"Nutanix/Cluster/" + ip_address + "/" + software_type + "/software_status", value:software_status);
        }
      }

      nutanix::log(msg: '\nProcessing Cluster Nodes...\n', lvl:2, config:config);
      foreach var node (nodes)
      {
        var node_ip = node.ip;
        var node_type = node.type;
        var node_version = node.version;

        set_global_kb_item(name:"Nutanix/Nodes/" + node_ip + "/ip", value:node_ip);
        set_global_kb_item(name:"Nutanix/Nodes/" + node_ip + "/version", value:node_version);
        set_global_kb_item(name:"Nutanix/Nodes/" + node_ip + "/type", value:node_type);

        hosts_to_inject[node_ip] = node_type;
      }

      cluster_count++;
    }
    else
    {
      # Count clusters without external IPs not sure what causes this
      cluster_skip_count++;
    }
  }

  nutanix::log(msg:"Discovered Cluster Count: " + cluster_count + '\n', lvl:2, config:config);
  nutanix::log(msg:"Discovered Cluster skipped Count: " + cluster_skip_count + '\n', lvl:2, config:config);

  var kb = { "host/injected/integration": "Nutanix" };
  var injected = 0;

  # Centralized the collection of hosts and injections, since we pull hosts/vms from 3 locations
  foreach (ip in keys(hosts_to_inject))
  {
    nutanix::log(msg:"Injecting Discovered Nutanix " + hosts_to_inject[ip] + " -> " + ip + '\n', lvl:3, config:config);

    # Skip injecting 127.0.0.1, it is collected from Nutanix but should not be scanned this way.
    if ("127.0.0.1" >!< ip)
    {
      inject_host(hostname:ip, kb:kb);
      injected++;
    }
  }
  if (!injected)
  {
    nutanix::log(msg:"[Error] no hosts were injected.", lvl:1, config:config);
    return {success:FALSE};
  }
  return {success:TRUE};
}

mutex_lock(SCRIPT_NAME);

if (empty_or_null(get_global_kb_item("Nutanix/collected")))
{
  var res = collect_nutanix_data();

  set_global_kb_item(name:"Nutanix/collected", value:res.success);
}
else
{
  var collection_ip = get_global_kb_item("Nutanix/DataCollection/CollectionIP");
  spad_log(message:"Nutanix data has already been collected. Check results from " + collection_ip + " for the debugging log.");
}

mutex_unlock(SCRIPT_NAME);

var collected = get_global_kb_item_or_exit("Nutanix/collected", exit_code: 1, msg: "Data collection for Nutanix failed.");

if (!collected)
{
  var msg = "No information was collected from Nutanix Prism Central.";
  report_error(title:"Unable to collect Nutanix Prism Central data", message:msg, severity:1);

  exit(1, msg);
}

# Has Nutanix data collection already ran for this host?
if (!empty_or_null(get_kb_item("Host/Nutanix/DataCollection/ran")))
{
  exit(0);
}

# Current host we are running on for linking the collected data
var target_ip = get_host_ip();

var cluster_ip = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/ip");
var node_ip = get_global_kb_item("Nutanix/Nodes/" + target_ip + "/ip");
var nutanix_port = get_kb_item("Host/Nutanix/config/port");

var version, report;

# Reports cluster data
if (!empty_or_null(cluster_ip))
{
  var service = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/service");
  version = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/version");
  var lts = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/lts");
  var full_version = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/full_version");
  var arch = get_global_kb_item("Nutanix/Cluster/" + target_ip + "/arch");

  set_kb_item(name:"Host/Nutanix/Data/Service", value:service);
  set_kb_item(name:"Host/Nutanix/Data/Version", value:version);
  set_kb_item(name:"Host/Nutanix/Data/lts", value:lts);
  set_kb_item(name:"Host/Nutanix/Data/ip", value:cluster_ip);
  set_kb_item(name:"Host/Nutanix/Data/full_version", value:full_version);
  set_kb_item(name:"Host/Nutanix/Data/arch", value:arch);

  report =
    'Collected Nutanix Data\n\n' +
    'Service: ' + service + '\n' +
    'Version: ' + version + '\n' +
    'Full Version: ' + full_version + '\n' +
    'LTS: ' + lts + '\n' +
    'Arch: ' + arch + '\n';

  security_report_v4(port:nutanix_port, extra:report, severity:SECURITY_NOTE);
}
# Reports node data
else if (!empty_or_null(node_ip))
{
  version = get_global_kb_item("Nutanix/Nodes/" + target_ip + "/version");
  var type = get_global_kb_item("Nutanix/Nodes/" + target_ip + "/type");

  set_kb_item(name:"Host/Nutanix/Data/Node/Ip", value:node_ip);
  set_kb_item(name:"Host/Nutanix/Data/Node/Version", value:version);
  set_kb_item(name:"Host/Nutanix/Data/Node/Type", value:type);

  report = 
    'Collected Nutanix Data :\n\n' +
    'IP Address: ' + node_ip + '\n' +
    'Version: ' + version + '\n' +
    'Type: ' + type + '\n';

  security_report_v4(port:nutanix_port, extra:report, severity:SECURITY_NOTE);
}

set_kb_item(name:"Host/Nutanix/DataCollection/ran", value:TRUE);
