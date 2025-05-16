#TRUSTED 31f5f70b3e40b26dd696dbe9b627d48dd22714422966708a6514a4b6c7e9a28986f1af918f8fb269a3823e65d948c586c5a0c8c87c484985a40515f7517c5d86fa6e0bdec672dee5f2c257e1befd8362aad4400b899e86984e464286c4a0ba14fe7b6e04ee0a0f1f5799bf52877a31e07f33adf4d63dcccb91bf695c955aa1da79c5c1c592c6fd8761eb1bae07d444dd57416e2ed788cff462b15cdb70b963ded4b3e64b93a8de5c51f8b68c532890c7c7db86c7c7e757a652df32c9c219e0f7bf4271d232629b2778b21c271b44bba668a345e657617f01b23e60349c1582b8b77a74f83a0e0da86d5748de5d86a0475d1e3f3175a8da340770104587c838e3f6c7798c268dcdb239d465d44b948c491007595a3f259f5fab887113f332da420a969d396e8737373ac64a7ed0405e38cb78a06f11550a0c940d939d3ac0737ff0f1af1df50e569d178e22e3f65adc4815842448b34e254038a105e37005d57f2912c3e84836fb8b111c02a0c28ed0f2d38bd86897f413f6ac77e77e3edff0cf4f7a6585a21825f3a3ada3e5d889b4c5ce994b1324b61721d35a32f491f8c352d7ad33338aa01ebba02c74a63920d72c48c9aa1b111d1143ddd2829fac3c433818dc8b740b19f7b792b44c088e4d07aba3b7f92c118326858a6eed1a3d28998d23a8f37abeda1544906d865f9dda939a11a3d00ea115ccaed0314b46cfeb94d9
#TRUST-RSA-SHA256 6944832b65b751c6d5ed38da83a4deff9fe5d1799143943b45b45e834e472abd664514339d30994a073eecbda2369e9ecbcf0be9592346f8faf1edf95a3ec1dba928fd5aef661b1e7c733c2ee8f9fb45f4db05b60ed8995967ad327413b05fb51a506dbe191c8174cfcc136c975b298b9d78f4057bf68b9c1fe4adc4c1935ab5b36310bbd4f16ac3797083a5632559a31e75763f4fb6d0209423f8928c6dbce6d276a887646e1e1254274f245165f1edcfc860941707f7300968ac63275f192279eb0e91ffa14cb0f36ac1e775271688ec5414016aac566490eb253bd8ae5bdc2d856b4cdb4ae52b10e5b78c2b3f150535e1016a52d1ffedc90e9138da1ed1acfe96c3216c718bd700ced6ba98fbc9577d8a5f90aff10df365c7dfb97e4e71215c9945a881de0aeb7fa04b5a7f9b450fe5e2b3223bf7f62bb8340177ec7f03c1ca7cf86228e277a3c78ddcbf35832a9cb50cdf3cd1af78886e92990fd5caf60caa2e04536adb44b47193beb0d01252a0b0c0d6a3f451bc12cd87a42b2f2cd06fd629c47c7ad4b52e59cb0b4603416a0a9e0819024c04f389e13b096f4e85e94b0f76da7928962a6cb1bc7f07e48dbe586d70f54d1cef77e4b524c062f319a13f8629c4ab8e580af65163bad351019a11b9950c837b154e324a8c340c9fcbdeaade457549d87287289b6c02d1f917982e318788e8c9b8d7c10b82f00477e074fa
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# netstat.inc
#
# Revision: 1.07

include('compat_shared.inc');
include('install_func.inc');
include('network_func.inc');
include('debug.inc');
include('nessusd_product_info.inc');

namespace netstat
{
  var TAP = 0;
  var DEFAULT_REPORT = 10;

  var states = [
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "LISTENING", #windows
    "CLOSING",
    "UNKNOWN", #valid UDP state
    "ESTAB", # ss
    "SYN-SENT", # ss
    "SYN-RECV", # ss
    "FIN-WAIT-1", #ss
    "FIN-WAIT-2", #ss
    "TIME-WAIT", #ss
    "UNCONN", #ss valid UDP state
    "CLOSE-WAIT", #ss
    "LAST-ACK", #ss
  ];

  var netstat_obj_template = {
    'proto':'',
    'local_addr':'',
    'local_port':'',
    'foreign_addr':'',
    'foreign_port':'',
    'state':''
  };

  # to help make the regex a little bit cleaner
  var ipv4addr = '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+';
  var ipv6addr = '[a-f0-9:]+(?:%[0-9a-z]+)?';
  var unspec_ipv4 = '0\\.0\\.0\\.0';
  var unspec_ipv6 = ':+(?:%[0-9a-z]+)?';
  # technically it looks like an interace name can contain almost anything. let's be reasonably sane here, though.
  var ss_interface = '%lo|%[a-z]+[0-9]+';

  # supports IPv4, IPv6, IPv6 zone ids
  var win_open_port_regex = '^[ \t]*(TCP|UDP)[ \t]+(?|(' +ipv4addr+ ')|\\[(' +ipv6addr+ ')\\]|(\\*)):([0-9]+)[ \t]+(?|(' +unspec_ipv4+ ')|(\\[?' +unspec_ipv6+ '\\]?)|(\\*)):(?:[0-9]+|\\*)(?:[ \t]+LISTENING)?';

  # unix regex supports ipv6/ipv4 embedded address
  # tcp 0 0 ::ffff:192.168.1.3:7001 :::* LISTEN (ipv6/ipv4 embedded address)
  var nix_open_port_regex = '^(tcp|udp)4?6?[ \t].*[ \t]+(?|(?:::ffff[:.])?(' +ipv4addr+ ')|(' +ipv6addr+ ')|(\\*))[:.]([0-9]+)[ \t]+(?|(' +unspec_ipv4+ ')|(' +unspec_ipv6+ ')|(\\*))[:.](?:[0-9]+|\\*)(?:[ \t]+LISTEN)?';

  var nix_ss_open_port_regex = '^(tcp|udp)4?6?[ \t]+(?:[ \t]+(?:LISTEN|UNCONN))[ \t]+\\d+[ \t]+\\d+[ \t]+(?|(?:::ffff[:.])?(' + ipv4addr + ')|\\[(' + ipv6addr + ')\\]|(\\*))(?:' +ss_interface+ ')?[:.]([0-9]+)[ \t]+(?|(' + unspec_ipv4 + ')|\\[(' + unspec_ipv6 + ')\\]|(\\*))[:.](?:[0-9]+|\\*)';

  # supports IPv4, IPv6, IPv6 zone ids
  var win_all_states_regex = '^[ \t]*(TCP|UDP)[ \t]+(?|(' + ipv4addr + ')|\\[?(' + ipv6addr + '))\\]?:([0-9]+)[ \t]+(?|(' + ipv4addr + ')|(\\[?' + ipv6addr + '\\]?)|(\\*)):([0-9]+|\\*)(?:(?:[ \t])+([A-Z_]+))?';

  # unix regex supports ipv6/ipv4 embedded address
  # tcp 0 0 ::ffff:192.168.1.3:7001 :::* LISTEN (ipv6/ipv4 embedded address)
  var nix_all_states_regex = '^(tcp|udp)4?6?[ \t].*[ \t]+(?|(?:::ffff[:.])?('+ipv4addr+')|(' + ipv6addr + ')|(\\*))[:.]([0-9]+)[ \t]+(?|('+ipv4addr+')|(' + ipv6addr + ')|(\\*))[:.]([0-9]+|\\*)(?:[ \t]+)?([A-Z_]+)?';

  var nix_ss_all_states_regex = '^(tcp|udp)4?6?[ \t]+(?:[ \t]+([A-Z]+))[ \t]+\\d+[ \t]+\\d+[ \t]+(?|(?:::ffff[:.])?(' + ipv4addr + ')|\\[(' + ipv6addr + ')\\]|(\\*))(' +ss_interface+ ')?[:.]([0-9]+)[ \t]+(?|(' + ipv4addr + ')|\\[(' + ipv6addr + ')\\]|(\\*))[:.]([0-9]+|\\*)';

  function pread_test_wrapper(cmd, argv)
  {
    if ( ! defined_func("pread") )
      exit(1, "The NASL 'pread()' function is not defined.");
    if ( get_kb_item("Test_Plans/lcx/islocalhost_overwrite") )
      return get_kb_item("Test_Plans/netstat_portscan/pread");

    return pread_wrapper(cmd:cmd, argv:argv);
  }

  ##
  # Attempts to find the local netstat or ss binary, runs it, returns results
  # This function will audit if it cannot identify a binary to run.
  #
  # @param [fn:string] Name of the calling function (optional)
  # @param [msg:string] Message to be logged in debugging log
  #
  # @remark Plugins that call this function must have nessus_product_setup.nasl as a dependency for the "nessus/os" KB item
  #
  # @ return string netstat run output
  ##
  function run_localhost_netstat()
  {
    var netstat_cmd, buf;
    var bin = 'netstat';
    var netstat_wmi  = get_preference('local_portscan.netstat_wmi');

    var os = get_kb_item_or_exit("nessus/os");

    if ("WINDOWS" >< toupper(os))
    {
      if (netstat_wmi == 'no')
        exit(0, 'WMI Netstat option is disabled, and must be enabled for this plugin to run.');
      else netstat_cmd = "C:\Windows\System32\netstat.exe";
    }
    else
    {
      if (file_stat("/bin/netstat") > 0 )
      {
        netstat_cmd = "/bin/netstat"; # Path on most unix machines
      }
      else if (file_stat("/usr/sbin/netstat") > 0 )
      {
        netstat_cmd = "/usr/sbin/netstat"; #path on Mac
      }
      else if (file_stat('/usr/bin/ss') > 0) #centos
      {
        netstat_cmd = '/usr/bin/ss';
        bin = 'ss';
      }
      else if (file_stat('/usr/sbin/ss') > 0) #ubuntu
      {
        netstat_cmd = '/usr/sbin/ss';
        bin = 'ss';
      }
      else if (file_stat('/sbin/ss') > 0) #debian
      {
        netstat_cmd = '/sbin/ss';
        bin = 'ss';
      }
      else
      {
        audit(AUDIT_PATH_NOT_DETERMINED, "netstat binary");
      }
    }

    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'netstat_cmd: '+netstat_cmd+', bin: '+bin+'\n');

    buf = pread_test_wrapper(cmd: netstat_cmd, argv: make_list(bin, "-a", "-n"));
    return buf;
  }

  function process_netstat_win_line_open_ports(line)
  {
    return pregmatch(pattern: netstat::win_open_port_regex, string: line, icase: 0);
  }

  function process_netstat_nix_line_open_ports(line)
  {
    return pregmatch(pattern: netstat::nix_open_port_regex, string: line, icase: 1);
  }

  function process_ss_nix_line_open_ports(line)
  {
    return pregmatch(pattern: netstat::nix_ss_open_port_regex, string: line, icase: 1);
  }

  function parse_netstat_line(line)
  {
    var netstat_obj = {};
    var matched = NULL;

    # Unix ss
    matched = pregmatch(pattern: netstat::nix_ss_all_states_regex, string: line, icase: 1);
    if (!empty_or_null(object: matched))
    {
      /*
      ss order:
      0: full match
      1: proto
      2: state
      3: local_addr
      4: local interface
      5: local_port
      6: foreign_addr
      7: foreign_port
      */
      if (!empty_or_null(object:matched[1]))
        netstat_obj['proto'] = matched[1];
      if (!empty_or_null(object:matched[3]))
        netstat_obj['local_addr'] = matched[3];
      if (!empty_or_null(object:matched[4]))
        netstat_obj['local_intf'] = matched[4];
      if (!empty_or_null(object:matched[5]))
        netstat_obj['local_port'] = matched[5];
      if (!empty_or_null(object:matched[6]))
        netstat_obj['foreign_addr'] = matched[6];
      if (!empty_or_null(object:matched[7]))
        netstat_obj['foreign_port'] = matched[7];
      if (!empty_or_null(object:matched[2]))
        netstat_obj['state'] = matched[2];
      else
        netstat_obj['state'] = "";
    }
    else # netstat
    {
      # Windows netstat
      matched = pregmatch(pattern: netstat::win_all_states_regex, string: line, icase: 0);

      # Unix netstat
      if (empty_or_null(matched))
        matched = pregmatch(pattern: netstat::nix_all_states_regex, string: line, icase: 1);

      if (!empty_or_null(object: matched))
      {
        /*
        netstat nix & win order:
        0: full match
        1: proto
        2: local_addr
        3: local_port
        4: foreign_addr
        5: foreign_port
        6: state
        */
        if (!empty_or_null(object:matched[1]))
          netstat_obj['proto'] = matched[1];
        if (!empty_or_null(object:matched[2]))
          netstat_obj['local_addr'] = matched[2];
        if (!empty_or_null(object:matched[3]))
          netstat_obj['local_port'] = matched[3];
        if (!empty_or_null(object:matched[4]))
          netstat_obj['foreign_addr'] = matched[4];
        if (!empty_or_null(object:matched[5]))
          netstat_obj['foreign_port'] = matched[5];
        if (!empty_or_null(object:matched[6]))
          netstat_obj['state'] = matched[6];
        else
          netstat_obj['state'] = "";
      }
    }
    return netstat_obj;
  }

  ##
  # Parses netstat or sscommand output into a dictionary (array) of relevant
  # parts.
  #
  # @param [cmd_output:string] output of netstat or ss command from win/nix
  #
  # @ return list list of array with keys. empty if errors or nothing relevant.
  ##
  function parse_complete_netstat_output(cmd_output)
  {
    var parsed_line, proto, local_addr, local_port, foreign_addr, foreign_port, state, netstat_obj;
    var lines = split(cmd_output);

    var parsed_netstat = [];
    foreach var line (lines)
    {
      netstat_obj = {};
      line = chomp(line);

      netstat_obj = netstat::parse_netstat_line(line:line);
      if (empty_or_null(object: netstat_obj ))
        continue;

      append_element(var:parsed_netstat, value:netstat_obj);
      dbg::detailed_log(lvl:4, src:FUNCTION_NAME, msg:'line: '+line+', netstat_obj: '+obj_rep(netstat_obj));
    }

    return parsed_netstat;
  }

  ##
  # Gets a list of listening ports from netstat output that's been parsed with
  # parse_complete_netstat_output().
  #
  # @param [parsed_netstat:list] list of arrays from parse_complete_netstat_output()
  # @param [include_local:bool]  default FALSE. TRUE: include listeners on 127.0.0.1 etc.
  #
  # @ return list of port numbers
  ##
  function get_listening_ports(parsed_netstat, include_local)
  {
    var listening_ports = [];
    if (empty_or_null(object: include_local))
      include_local = FALSE;
    foreach (var entry in parsed_netstat)
    {
      if (
        (empty_or_null(object:entry.state) && toupper(entry.proto) == 'UDP') ||
        (toupper(entry.state) == 'UNCONN' && toupper(entry.proto) == 'UDP') ||
        ('LISTEN' >< toupper(entry.state))
      )
      {
        if (!include_local && is_private_addr(addr:entry.local_addr) == 1)
          continue;
        if (!contains_element(var:listening_ports, value:entry.local_port))
        {
          append_element(var: listening_ports, value: entry.local_port);
        }
      }
    }
    return listening_ports;
  }

  ##
  # Determines if there are non-private addresses connecting to listening
  # ports.
  #
  # @param [parsed_netstat:array] output of parse_complete_netstat_output()
  # @param [listening_ports:list] list of listening ports or output from
  #                               get_listening_ports()
  # @param [all:bool] TRUE: enumerate all non-private connecting addresses
  #                  FALSE: enumerate only the first
  #
  # @ return NULL if error
  # @ return list of arrays if found. array has keys ip & port
  ##
  function get_non_private_inbound_connections(parsed_netstat, listening_ports, all)
  {
    if (empty_or_null(object: listening_ports))
      listening_ports = get_listening_ports(parsed_netstat:parsed_netstat);
    if (typeof(listening_ports) != 'array')
      return NULL;
    if (typeof(parsed_netstat) != 'array')
      return NULL;
    if (empty_or_null(object:all))
      all = FALSE;

    var output = [];

    foreach var entry (parsed_netstat)
    {
      foreach var port (listening_ports)
      {
        if (entry.local_port != port)
          continue;
        if (is_private_addr(addr:entry.foreign_addr) == 1 ||
          entry.local_addr =~ unspec_ipv4 ||
          entry.local_addr =~ unspec_ipv6 ||
          entry.foreign_addr =~ unspec_ipv4 ||
          entry.foreign_addr =~ unspec_ipv6 ||
          entry.local_addr == '*' ||
          entry.foreign_addr == '*')
          continue;
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'found: parsed_netstat entry: '+obj_rep(entry)+', listening_ports: '+obj_rep(listening_ports)+', all: '+obj_rep(all)+'\n');
        append_element(var:output, value:{'ip':entry.foreign_addr,'port':entry.local_port});
        if (!all && max_index(output) >= DEFAULT_REPORT)
          break;
      }
      if (!all && max_index(output) >= DEFAULT_REPORT)
        break;
    }
    return output;
  }

  ##
  # Add port obtained from netstat port scan to the
  # available open ports on the system and create a
  # plugin output reporting the port as open.
  #
  # @param [proto:string] tcp or udp protocol used, defaults to tcp
  # @param [port:int] port number, required
  #
  # @return 1 on success, NULL on failure
  ##
  function add_port(proto, port)
  {
    var scanner_add_port_init_msg = "netstat add_port "+proto+"/"+port;
    dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:scanner_add_port_init_msg);

    if (isnull(get_kb_list("report_max_ports/"+SCRIPT_NAME)))
    {
      var report_max_ports = get_preference("report.max_ports");
      if (isnull(report_max_ports))
      {
        report_max_ports = "NULL";
      }
      else if (strip(report_max_ports) == "")
      {
        report_max_ports = "NO VALUE PROVIDED";
      }
      
      replace_kb_item(name:"report_max_ports/"+SCRIPT_NAME, value:report_max_ports);
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"report.max_ports = "+report_max_ports);
    }
    
    if (isnull(port))
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"add_port: port value is NULL.");
      return NULL;
    }
    
    if (port < 0 || port > 65535 )
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"add_port: Invalid value ("+port+").");
      return NULL;
    }
    
    if (nessusd_is_agent())
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Netstat port data is being added as an agent.");
      
      #This is manual addition to ports that bypasses the engine max_port setting
      # this block does not honor nessus rules files at this time.

      # Check the nessus.rules for this port to be exculded from the scan
      if (!rules_validate_target(port:port))
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Nessus rules prevent access to destination port destination "+get_host_ip()+"  port "+port);
        return NULL;
      }
      
      # obtain the plugin ID for the running plugin
      var env = nasl_environment(flags:ENV_PLUGIN);
      if(!empty_or_null(env['plugin_id']))
      {
        var plugin_id = env['plugin_id'];
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"plugin_id:"+plugin_id);
      }
      else
      { # This should never happen but is here as a catch
        var failed_plugin_id_msg = "failed to obtain plugin id for netstat port scanner causing it to fail to add the port "+port+".";
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:failed_plugin_id_msg);
        
        return NULL;
      }

      # proto defaults to TCP if not set in the engine, this replicates this default state
      if (isnull(proto)) proto = "tcp";
      
      # enigne call : snprintf(port_s, sizeof(port_s), "portscanner/%d/Ports/%s/%d", p->_runtime.get_plugin_id(), proto == NULL ? "tcp":proto, port);
      var portscanner_kb_key = "portscanner/"+plugin_id+"/Ports/"+proto+"/"+port;
      if (!isnull(get_kb_list(portscanner_kb_key)))
      {
        var portscanner_kb_key_exists = portscanner_kb_key + " already exists";
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:portscanner_kb_key_exists);
        return NULL;
      }

      replace_kb_item(name:portscanner_kb_key, value:1);

      # engine call : snprintf(port_s, sizeof(port_s), "Ports/%s/%d", proto == NULL ? "tcp":proto, port);
      var port_kb_key = "Ports/"+proto+"/"+port;
      if (isnull(get_kb_list(port_kb_key)))
      {
        replace_kb_item(name:port_kb_key, value:1);
      }
      
      #engine call : snprintf(port_s, sizeof(port_s), "Success/%d", p->_runtime.get_plugin_id());
      var success_plugin_id_kb_key = "Success/"+plugin_id;
      if (isnull(get_kb_list(success_plugin_id_kb_key)))
      {
        replace_kb_item(name:success_plugin_id_kb_key, value:1);
      }

      # Create a report for the open port 
      netstat::report_open_netstat_port(proto:proto, port:port);
    }
    else
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Netstat port data is being added as a non-agent.");
      # This is the default engine function used for adding ports discovered.
      # This call will use the max_ports setting and honor the nessus.rules 
      scanner_add_port(proto: proto, port: port);
    }

    return 1;
  }

  ##
  # Generate a plugin output for open ports found during netstat portscan
  #
  # @param [proto:string] tcp or udp protocol used
  # @param [port:int] port number
  #
  # @return NULL
  ##
  function report_open_netstat_port(proto, port)
  {
    var report = "Port "+port+"/"+proto+" was found to be open";
    dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:report);

    security_report_v4(port:port, proto:proto, severity:SECURITY_NOTE, extra:report);

    return NULL;
  }
}
