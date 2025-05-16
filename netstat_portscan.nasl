#TRUSTED a4d7e1927777574887f376f609c1a33f6e9959cc2c68610dcca4a0434378b922e32ab2cd29e2288ddab8dc4d333d45110fdc2119482ca03088b1f39949c4cd66f47bfcf63bd64fac2a58c6f996071c8542f883a97ed321cbacea718f138b451a730b596be1c0405b51188bf440866999a019815e84bc4ee813aa2a1eb5fcf9f74ba8db21d7e971b3e501c0b0f49ad01b2a81c55ece125c95b9307a54ae7791152827e88ef48248e71318bed051985637554200b6ae0b45d8e4eaf7ab2cc270e5792ef19f7cbeaae61e593c79d92d62dbfab0a4a4faf98aff0fa3704c5d3581e9c91336596e24c92a32b74cbbc01bc34c5ed6abc4608f44970a3eae3bc5d64e3c65e011495404bca86c3f817bcb924cd319a100a60c4c3cbdb280354daf4e27f69cb99c6e1c5409c778364821a825ecd176127c6927d9460943979220b80964ba1675d7c64f52072ee9b567d62ce1bdbc08e8c53d7d28d2f8290a3c5b8b71c4fc1a0243b787d0a5b0f6abe10ed7a5926f121bb56bf4de49a34922b2dab22328fc597f40224e6f0a748c42b5b35b2634cfd6777f346d4425f2f9028674272586576d361acbbe5f804b73f7a6d92f25c95fbc3d22f1b216b16b87a68ddd69be3a175c7465ab459f4ad0462854664f596ed6829345ce41ddc7efe00c63b3cd259a9990602af0dd411e9bf1c39fcb35e91f7505c92960e287b5d48ce55586dbabd1bb
#TRUST-RSA-SHA256 9f36092ee1f10216ccd4228972f45e08ea38a312d32d1381fe9f607238dd89bcef5e88e3c49dd168cfc51b57ae23b342347ba80e9f969ddd5291962f4f6e17430081737fb11dec423a8cb012a91de83f5351ef44f1a33af93bf4ae8d19bfb8da5d1ca1a279ab8a8a10fe61565d837e82b44b9b79fef0643c544ae74c44484bd96daae046d3b718b14b2f4c8cbf9a1c0ab11cb9f13584956fcce4bc7f744decf6d31927a8a627ca83b5529cbbf8b41a440900c8f2668b256fc1ffa8bd3af232100d0de54d7b852c088f61dd2ddc90762b9bd799c09f668e1da8b801e30d2fd96d5feabf457a743f7bee2f6c0458bbf87c86e4001a749043177956e0fd1b0baa2d4a431c544308c8e70373e4e90e678aa28c54cb7e513736c904efda7ee61f190ff051e79141800ec394c45959b790339cfe70fcf60e2fec81d2808e3af20ee4d4513f2bc6fc45966e5bc6273e15364aa9c86f77799ca9436e98ac92feb55394258fa4457bf76f225ba2e3c75e78c9cb90351b765ed6d59b1a69b0e09f414258d812825be51fec3f47948e2660ab3b16ddb375aa94f7efa026806f6c3033133976764cc67df8ead71200d20ea04376bfacb37bbfb8258cccfde7d9cfabdad495bb4e16b32caf26b07ef91415a1ed8272cefc25d2701f8493d4596989365d666cc8fd8be7d16093e898f0f11184b3b5824091006b384b3c3e9b4d08c5b3a85cb466
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(14272);
  script_version("1.109");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_name(english:"Netstat Portscanner (SSH)");

  script_set_attribute(attribute:'synopsis', value:
"Remote open ports can be enumerated via SSH.");
  script_set_attribute(attribute:'description', value:
"Nessus was able to run 'netstat' on the remote host to enumerate the
open ports. If 'netstat' is not available, the plugin will attempt to use 'ss'.

See the section 'plugins options' about configuring this plugin.

Note: This plugin will run on Windows (using netstat.exe) in the
event that the target being scanned is localhost.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Netstat");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_SCANNER);
  script_family(english:"Port scanners");

  script_copyright(english:"This script is Copyright (C) 2004-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ping_host.nasl", "ssh_settings.nasl", "portscanners_settings.nasl", "ssh_rate_limiting.nasl", 'nessus_product_setup.nasl');
  script_exclude_keys("Host/OS/ratelimited_sonicwall", "Host/OS/ratelimited_junos", "Host/OS/ratelimited_omniswitch");
  script_timeout(600);
  exit(0);
}

include("ports.inc");
include("lcx.inc");
include("agent.inc");
include("ssh_lib.inc");
include("ssh_compat.inc");
include("netstat.inc");

function run_cmd_by_sshlib(cmd)
{
  local_var session, channel, login_res, escl_method, escl_extra;

  var buf = NULL;
  session = new("sshlib::session");
  login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:TRUE);
  if(!login_res)
  {
    session.close_connection();

    # If it failed, remove the failure so that plugins down the chain can verify after
    # service detection.
    rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed");
    return NULL;
  }

  session.set_recv_timeout(60);
  escl_method = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + session.get_kb_connection_id() + "/escalation_type");
  if(!escl_method || "Nothing" >< escl_method)
  {
    buf = session.run_exec_command(command:cmd, cmd_timeout_min:120);
    if(empty_or_null(buf))
    {
      channel = session.open_shell(shell_handler:new("sshlib::sh_shell_handler"));
      if(!isnull(channel))
        buf = session.run_shell_command(channel:channel, command:cmd);
    }
  }
  else
  {
    channel = session.open_shell(shell_handler:new("sshlib::sh_shell_handler"));
    if(!isnull(channel))
    {
      escl_extra = sshlib::get_kb_args(kb_prefix:("Secret/" + sshlib::SSH_LIB_KB_PREFIX + session.get_kb_connection_id() + "/escalation_extra"));
      channel.shell_handler.set_priv_escalation(type:escl_method, extra:escl_extra);
      buf = session.run_shell_command(channel:channel, command:cmd, force_priv_escl:TRUE);
    }
    if(empty_or_null(buf))
    {
      buf = session.run_exec_command(command:cmd, cmd_timeout_min:120);
    }
    if(empty_or_null(buf))
    {
      channel.shell_handler.unset_priv_escalation();
      if(!isnull(channel))
        buf = session.run_shell_command(channel:channel, command:cmd);
    }
  }

  session.close_connection();
  return buf;
}

var netstat_ssh = get_preference('local_portscan.netstat_ssh');

if (netstat_ssh == 'no')
  exit(0, 'SSH Netstat option is disabled, and must be enabled for this plugin to run.');

if(isnull(get_kb_item("/tmp_start_time")))
  replace_kb_item(name: "/tmp/start_time", value: unixtime());

if ( get_kb_item("PortscannersSettings/run_only_if_needed") &&
     get_kb_item("Host/full_scan") )
  exit(0, "The remote host has already been port-scanned.");

if (get_kb_item("Host/OS/ratelimited_sonicwall") ||
    get_kb_item("Host/OS/ratelimited_junos") ||
    get_kb_item("Host/OS/ratelimited_omniswitch"))
  exit(1,"This plugin does not run against rate limited devices.");

# If plugin debugging is enabled, enable packet logging
if(get_kb_item("global_settings/enable_plugin_debugging"))
  SSH_LOG_PACKETS = TRUE;

var buf = "";
var ssh_banner = "";
var n_tcp = 0;
var n_udp = 0;

var port22, timeout, cmd, agent_ip, ret, i, msg, res;

# On the local machine, just run the command
if (lcx::check_localhost())
{
  buf = netstat::run_localhost_netstat();
  if ( buf )
  {
    set_kb_item(name:"Host/netstat", value:buf);
    set_kb_item(name:"Host/netstat/method", value:"local");
    if (agent())
    {
      agent_ip = agent_get_ip();
      if(!isnull(agent_ip))
        report_xml_tag(tag:"host-ip", value:agent_ip);
    }
  }
  else exit(1, "Failed to run the command 'netstat -a -n' on localhost.");
}
else if ( get_kb_item("Secret/SSH/login") )
{
  port22 = sshlib::kb_ssh_transport();
  if ( port22 && get_port_state(port22) )
  {
    res = info_connect();
    if ( res )
    {
      ssh_banner = ssh_exchange_identification();

      if (info_t == INFO_SSH)
        ssh_close_connection();

      if (
         "-cisco-" >< tolower(ssh_banner) ||
         "-cisco_" >< tolower(ssh_banner)
      ) exit(0, 'The netstat portscanner doesn\'t run against Cisco devices.');
    }
  }

  # Need to set try none for Sonicwall
  set_kb_item(name:"/tmp/ssh/try_none", value:TRUE);
  timeout = get_ssh_read_timeout();
  if (timeout <= 5) set_ssh_read_timeout(10);

  if ("force10networks.com" >< ssh_banner) sleep(1);

  ret = info_connect();

  # nb: Sonicwall needs a delay between the initial banner grab
  #     and  calling 'ssh_open_connection()'.
  if (
    !ret &&
    "please try again" >< get_ssh_error()
  )
  {
    for (i=0; i<5 && !ret; i++)
    {
      # We need to unset login failure if we are going to try again
      if(get_kb_item("SSH/login/failed")) rm_kb_item(name:"SSH/login/failed");
      sleep(i*2);
      ret = info_connect();
    }
  }

  cmd = "cmd /c netstat -an";
  if (ret)
  {
    buf = info_send_cmd(cmd:cmd, nosudo:TRUE, timeout:60);
  }
  else
  {
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }

  if (get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed") &&
      get_kb_item("SSH/login/failed"))
  {
    exit(1, "Failed to open an SSH connection.");
  }

  if('Command Line Interface is starting up, please wait' >< buf)
  {
    if (info_t == INFO_SSH)
      ssh_close_connection();
    exit(0, 'The netstat portscanner doesn\'t run against Cisco devices.');
  }

  if ("LISTENING" >!< buf && "0.0.0.0:0" >!< buf && "*.*" >!< buf)
  {
    # Brocade
    if (
      !buf &&
      'rbash: sh: command not found' >< ssh_cmd_error()
    )
    {
      if(!ret)
      {
        res = info_connect();
        if (!res) exit(1, "Failed to reopen an SSH connection.");
      }

      cmd = "netstat -an";
      buf = info_send_cmd(cmd:cmd, timeout:60);
    }
    # NetApp Data ONTAP
    else if (
      !buf &&
      "cmd not found.  Type '?' for a list of commands" >< ssh_cmd_error()
    )
    {
      if (info_t == INFO_SSH)
        ssh_close_connection();
      res = info_connect();
      if (!res) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "netstat -an";
      buf = info_send_cmd(cmd:cmd, nosudo:TRUE, timeout:60);
    }
    #NetApp Data ONTAP clustered
    else if (
      !buf &&
      "Error: Ambiguous command" >< ssh_cmd_error() ||
      "is not a recognized command" >< ssh_cmd_error()
    )
    {
      if (info_t == INFO_SSH)
        ssh_close_connection();
      sock_g = info_connect();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "system node run -node local -command netstat -an";
      buf = info_send_cmd(cmd:cmd, nosudo:TRUE, timeout:60);
      if ( !buf && "is not a recognized command" >< ssh_cmd_error() )
      cmd = "node run -node local -command netstat -an";
      buf = info_send_cmd(cmd:cmd, nosudo:TRUE, timeout:60);
      if ( !buf && "is not a recognized command" >< ssh_cmd_error() )
      cmd = "run -node local -command netstat -an";
      buf = info_send_cmd(cmd:cmd, nosudo:TRUE, timeout:60);
    }

    # ScreenOS
    else if (
      !buf &&
      "-NetScreen" >< ssh_banner
    )
    {
      if (info_t == INFO_SSH)
        ssh_close_connection();
      res = info_connect();
      if (!res) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "get socket";
      buf = info_send_cmd(cmd:cmd, nosudo:TRUE, timeout:60);
    }
    else
    {
      if (info_t == INFO_SSH)
        ssh_close_connection();

      cmd = 'netstat -a -n';
      /**
      - sshlib
      -- If there are no escalation credentials
      --- Try exec
      --- If that doesn't work, try sh shell handler
      -- If there are escalation credentials
      --- Try sh shell handler
      --- If that doesn't work
      ---- Try exec without credentials
      ---- If that doesn't work, try sh shell handler without credentials
      **/

      buf = run_cmd_by_sshlib(cmd: cmd);
      if ('command not found' >< buf || 'No such file or directory' >< buf || ' not found, but can be installed with:' >< buf)
      {
        dbg::detailed_log(
          lvl:3,
          src:SCRIPT_NAME,
          msg:"netstat not found, trying ss.",
          msg_details: {
            'netstat output' : {lvl:3, value:buf}
          }
        );
        # if netstat fails, try ss as a separate command
        // try ss
        # centos: /usr/bin/ss -a -n
        # ubuntu: /usr/sbin/ss -a -n
        # debian: /bin/ss -a -n
        cmd = '(/usr/sbin/ss -n -a 2>/dev/null && echo 1)|| (/bin/ss -n -a 2>/dev/null && echo 2)|| (/usr/bin/ss -n -a 2>/dev/null && echo 3)';

        buf = run_cmd_by_sshlib(cmd: cmd);
      }
    }

    if (
      !buf ||
      "Cmd exec error" >< buf ||
      "Cmd parse error" >< buf ||
      "command parse error before" >< buf ||
      "(Press 'a' to accept):" >< buf ||
      "Syntax error while parsing " >< buf ||
      ' not found, but can be installed with:' >< buf
    )
    {
      if (info_t == INFO_SSH)
        ssh_close_connection();
      exit(1, "The 'netstat' command failed to be executed.");
    }
  }
  if (info_t == INFO_SSH)
    ssh_close_connection();
  set_kb_item(name:"Host/netstat", value:buf);
  set_kb_item(name:"Host/netstat/method", value:"ssh");
  if ('/ss' >< cmd)
    set_kb_item(name:'Host/netstat/cmd', value:'ss');
}
else
{
  exit(0, "No credentials are available to login to the host.");
}

var ip = get_host_ip();
var lines = split(buf);
var scanned = 0;

var check = get_kb_item("PortscannersSettings/probe_TCP_ports");

var unscanned_closed, tested_tcp_ports, tested_udp_ports;

if ("yes" >< get_preference("unscanned_closed"))
  unscanned_closed = TRUE;
else
  unscanned_closed = FALSE;

if (unscanned_closed)
{
  tested_tcp_ports = get_tested_ports(proto: 'tcp');
  tested_udp_ports = get_tested_ports(proto: 'udp');
}
else
{
  tested_tcp_ports = make_list();
  tested_udp_ports = make_list();
}

var discovered_tcp_ports = make_array();
var discovered_udp_ports = make_array();

var v, last_seen_proto, proto, state, local_ip, local_port;
var addr, port, checktcp, addr_parts, soc;
var parsed_lines;

foreach var line (lines)
{
  line = chomp(line);
  # Windows - 2024 devnote: this plugin does not seem to run on windows
  v = netstat::process_netstat_win_line_open_ports(line:line);

  # Unix
  if (isnull(v))
    v = netstat::process_netstat_nix_line_open_ports(line:line);

  if (isnull(v))
    v = netstat::process_ss_nix_line_open_ports(line:line);

  # Solaris 9 / NetApp
  if (isnull(v))
  {
    if (last_seen_proto)
    {
      if (last_seen_proto == 'udp')
      {
        v = pregmatch(pattern: '^[ \t]*(?:::ffff[:.])?(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle', string: line);
        if (isnull(v)) v = pregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+(\\*\\.\\*|[0-9.]+)[ \t]+[0-9]+[ \t]+[0-9]+$', string: line);
      }
      else
        v = pregmatch(pattern: '^[ \t]*(?:::ffff[:.])?(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)', string: line);

      if (! isnull(v))
      {
        # "Fix" array
        v[3] = v[2]; v[2] = v[1]; v[1] = last_seen_proto;
      }
    }
    if (isnull(v))
    {
      v = pregmatch(pattern: '^(TCP|UDP)(: +IPv4)?[ \t\r\n]*$', string: line);
      if (isnull(v)) v = pregmatch(pattern: '^Active (TCP|UDP) (connections|sockets) \\(including servers\\)[ \t\r\n]*$', string: line);
      if (!isnull(v))
      {
        last_seen_proto = tolower(v[1]);
        v = NULL;
      }
    }
  }

  # ScreenOS
  # Socket  Type   State      Remote IP         Port    Local IP         Port
  #    1  tcp4/6  listen     ::                   0    ::                443
  #    2  tcp4/6  listen     ::                   0    ::                 23
  #    3  tcp4/6  listen     ::                   0    ::                 22
  #   67  udp4/6  open       ::                   0    ::                500
  if (isnull(v))
  {
    v = pregmatch(pattern:'^[ \t]*[0-9]+[ \t]+(tcp|udp)4/6[ \t]+(listen|open)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|::)[ \t]+[0-9]+[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|::)[ \t]+([0-9]+)[ \t]*', string:line, icase:TRUE);
    if (!isnull(v))
    {
      proto = v[1];
      state = v[2];
      local_ip = v[4];
      local_port = v[5];

      # "Fix" array
      v[1] = proto;
      v[2] = local_ip;
      v[3] = local_port;
    }
  }

  if (!isnull(v))
  {
    proto = tolower(v[1]);
    addr = v[2];
    port = int(v[3]);
    checktcp = (check && proto == "tcp");

    if (port < 1 || port > 65535)
    {
      msg = strcat('netstat_portscan(', ip, '): invalid port number ', port, '\n');
      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);
    }

    # Avoid reporting port allowances only for localhost
    addr_parts = split(addr, sep:".");
    if (addr_parts[0] == "127." || addr == "::1")
    {
      if (addr != ip)
      {
        msg = strcat('netstat_portscan(', ip, '): skipping localhost-specific line: ', line, '\n');
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);
        continue;
      }
      else if (addr == ip && "127.0.0.1" >< addr)
      {
        # this check corrects a problem where agent ip matches 127.0.0.1 localhost port offering
        msg = strcat('netstat_portscan(', ip, '): skipping IPv4 localhost-specific line: ', line, '\n');
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);
        continue;
      }
    }

    if (unscanned_closed)
    {
      if (
        (proto == "tcp" && ! tested_tcp_ports[port]) ||
        (proto == "udp" && ! tested_udp_ports[port])
      ) continue;
    }

    if (
      (proto == "tcp" && discovered_tcp_ports[port]) ||
      (proto == "udp" && discovered_udp_ports[port])
    ) continue;

    if (checktcp)
    {
      soc = open_sock_tcp(port);
      if (soc)
      { 
        netstat::add_port(proto: proto, port: port);
        close(soc);
      }
    }
    else
    {
      netstat::add_port(proto: proto, port: port);
    }

    if (proto == "tcp")
    {
      n_tcp ++;
      discovered_tcp_ports[port]++;
    }
    else if (proto == "udp")
    {
      n_udp ++;
      discovered_udp_ports[port]++;
    }
    scanned ++;
    parsed_lines = strcat(parsed_lines, line, '\r\n');
    msg = strcat('netstat_portscan(', ip, '): found valid line: ', line, '\n');
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);
  }

}


var check_debug_level = get_kb_item("global_settings/debug_level");
if ( !empty_or_null(parsed_lines) &&
     !empty_or_null(check_debug_level) &&
     int(check_debug_level) > 2 )
{
  replace_kb_item(name: "Host/netstat_debug_parsed_lines", value: parsed_lines);
}

if (scanned)
{
  set_kb_item(name: "Host/scanned", value: TRUE);
  set_kb_item(name: "Host/udp_scanned", value: TRUE);
  set_kb_item(name: "Host/full_scan", value: TRUE);

  set_kb_item(name:"NetstatScanner/TCP/OpenPortsNb", value: n_tcp);
  set_kb_item(name:"NetstatScanner/UDP/OpenPortsNb", value: n_udp);

  set_kb_item(name: "Host/TCP/scanned", value: TRUE);
  set_kb_item(name: "Host/UDP/scanned", value: TRUE);

  set_kb_item(name: "Host/TCP/full_scan", value: TRUE);
  set_kb_item(name: "Host/UDP/full_scan", value: TRUE);

  set_kb_item(name: 'Host/scanners/netstat', value: TRUE);
}

