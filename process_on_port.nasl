#TRUSTED 5f3963b0fbf6806206fcbd97e3f941c576af7a92c97f7cee1fc0bc5c535b8ec985b6ae4efca959e6d697acecba362e1545539b5938319ac47f1f29dd68da669306e9de20b3bfbbff2aae2fc3948c2162826b2d2b5013ee22e41434d5040cefe6839007f5953d92555bd4d35e77460e9036f54750162481ab7c66aa32d0ef49f64b079c48a17e187ba19fb4beed459e72597e070b424444d05af370a74675ec026de79c59f3e848be9b0c436e5e27d7bdaa84612dd7ce6289d4931630989d59968977588559dabb47ba3b371fa2fa9680950bee2763e00af455836ae64f8bf49a8aba86746a5520bc06902f02c51700f3962dd00a2ac23f40b59a4b02d0f3e45366f921389de3191223276de163c814f4a6505c8115ec80c347974374432c1bfbcbd7efca5d3ea6c0f0d294de44ec78dd430528176081d00cd61ad95a674353332c5c7e1bea70d1341d9258fbbd43047b2462f4e8b85c49c3dafdf33cd4ea4466e97eeccc959a9f908eaa151f4019720876646d821e27db09657387e8f3a157788562f3854edb3a011a665fe887f824dc35c62d6227850f00174532b2f2fa29cdab149e964497194831069c3ae14ab780549e19651f214eb130360979038d92ded0bd9c3f9ebcdb02fe2adb3ff8892dfa7629141815eedc30d403e21d5babba9bf0fe7e97dcf11000bea10f5da866f691c02e615d7bcbee67d9b597190c5eaab9
#TRUST-RSA-SHA256 0df6d5cd6d94e3440e056e6297027fa6ad3ebb15256d0fd19790028420cec0689ef71cae3f6a0a9b21e7f84a9ce2211b5154b5e42d492363b8039ce501f905490b290d3777ab03050ce5839782a0bd5f3ef12098a65402b1af6df2a24f8252769ccb5b3cd29b70dffc1acf2e780fe155c02b5566c116150cdccc764f5f8921ff3d66cfdf58aba910bf251a108596d1df7b7402f829da80cc3680a68afdbdc4642d0c0636b1def91da0051ef99d5880600fe66b5ae4d681fe74f83eb42ab9200f13b591ca011fa8f209d02a46bf76209c1c4a150fcbdf0ca4b85f4f53048265cbfaf74b416f93c31f02258b944e2658b33877c3c0efa191b01441125ae433fb6be132d6f52fd31deda37966e3ae39e4f4b429d31dd9589472331528570950f2eb6fec2fe4f21749ccf2768a55e452e1851b1d959a09b47c9fcf1cc00173088488b3abe9a25fb1ebec064df6ae8d3514177e93553e0cf6df30305f65b04d6ce9afe9b665e9d5132080b699d4f5192139560f2d5f0fd8c222dbb2fab5ec391b7d9e1a6ce94adcab48afddc7b01aa61dd485cb4149cec4c71691e428cb5ff04968ff6509e3f0f9c6f6229a8754f319c4c46fe6fbfe2cee32280712e4cde1d8e5bddd1061f51c00ce5e6d9a28e91d685dc95a40f3c36c7fa94f4f3ba6d54bc66e499fb350b1e3a63251d1a824967ac2c3ffa07484c8634c38aea49c570e5a8526668d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25221);
 script_version("1.29");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/05");

 script_name(english:"Remote listeners enumeration (Linux / AIX)");
 script_summary(english:"Finds the process listening on each port with netstat.");

 script_set_attribute(attribute:"synopsis", value:
"Using the supplied credentials, it was possible to identify the
process listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"By logging into the remote host with the supplied credentials, Nessus
was able to obtain the name of the process listening on the remote
port.

Note that the method used by this plugin only works for hosts running
Linux or AIX.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2007-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22, "nessus/product/agent");
 script_require_keys("Host/uname");

 exit(0);
}

include("compat_shared.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("local_detection_nix.inc");
include("process_on_port_parser.inc");

var cmdlines = make_array();
var cmdlines_enc = make_array();
var localaddrs = make_array();
var exes = make_array();
var pids = make_array();
var prelinked = make_array();
var md5s = make_array();

##
# Uses readlink, md5sum and cat to get executable, md5 and commandline of the target process
# @param pid PID of the target process
# @return An array containing {executable:string, commandline:string, b64_commandline:string}
# @remark This function can also write to md5s array if it finds a new broken executable link
##
function get_process_data(pid)
{
  if (pid <= 0) return NULL;
  
  var results = {};
  var exe = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C readlink \'/proc/$1$/exe\' 2>/dev/null', args:[pid]);
  if (strlen(exe) > 0) exe = chomp(exe);
  results['executable'] = exe;

  # check md5sum of process image for further verification if needed  (used in daemons_with_broken_links.nasl)
  if(isnull(md5s[pid]) && preg(pattern:"^(.+) \(deleted\)$", string:exe))
  {
    var exe_md5sum = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C md5sum \'/proc/$1$/exe\' 2>/dev/null', args:[pid]);
    var item = pregmatch(pattern:'^([a-zA-Z0-9]{32}) ', string: exe_md5sum);
    if(!isnull(item)) md5s[pid] = item[1];
  }

  var cmdline_pure = ldnix::run_cmd_template_wrapper(template:'LC_ALL=C cat \'/proc/$1$/cmdline\' 2>/dev/null', args:[pid]);
  
  var cmdline = join(split(cmdline_pure, sep:'\x00', keep:FALSE), sep:' ');
  var cmdline_enc = base64(str:cmdline_pure);
  results['commandline'] = cmdline;
  results['b64_commandline'] = cmdline_enc;

  return results;
}

##
# Parses nestat output from a qualifying host
# @param buf netstat -anp or ss -anp output from a host
# @param @line_parser A reference to function that parses either an ss or netstat output line
# @remark This function will fill cmdlines, localaddrs, exes, pids, prelinked and md5s global arrays
##
function fill_socket_data(buf, line_parser)
{
  var results, port, pid, socket, exe, process_info, cmdline, cmdline_enc;
  var lines = split(buf, keep:FALSE);
  foreach var line (lines)
  { 
    results = line_parser(line:line);
    
    if (isnull(results)) continue;
    
    port = results['port'];
    if (port < 0 || port > 65535) continue;
    proto = results['proto'];
    if (proto != "tcp" && proto != "udp") continue;

    socket = strcat(proto, '/', port);
    if (exes[socket]) continue;

    pid = results['pid'];
    process_info = get_process_data(pid:pid);
    if(isnull(process_info) || empty_or_null(process_info['executable'])) exe = results['executable'];
    else exe = process_info['executable'];
    if (strlen(exe) == 0) continue;

    localaddrs[socket] = results['address'];
    exes[socket] = exe;
    if (pid > 0) pids[socket] = pid;
    cmdline = process_info['commandline'];
    if (strlen(cmdline) > 0) cmdlines[socket] = cmdline;
    cmdline_enc = process_info['b64_commandline'];
    if (strlen(cmdline_enc) > 0) cmdlines_enc[socket] = cmdline_enc;
  }
}

var uname = get_kb_item_or_exit("Host/uname");
if (
  'Linux' >!< uname &&
  'AIX' >!< uname
) audit(AUDIT_HOST_NOT, "Linux / AIX");

enable_ssh_wrappers();
info_connect();

# nb: On Solaris, you can do this with a command like:
#
#     pfexec pfiles `ls /proc` 2>/dev/null | egrep '^[0-9]|port:'
#
#     The problem is that pfiles, as its man page warns, can cause a process
#     to stop while its being inspected by the tool, and that is to be
#     avoided in a production environment!

if ("Linux" >< uname)
{
  var buf = info_send_cmd(cmd:"prelink -p 2>/dev/null");
  var item;
  # sanity check
  if('objects found in prelink cache' >< buf)
  {
    foreach var entry (split(buf, sep:'\n', keep:FALSE))
    {
      # only interested in binaries, the code below
      # will filter out the libraries
      if(':' >< entry && entry !~ "\[0x[a-zA-Z0-9]+\]")
      {
        item = pregmatch(pattern:"^([^:]+):", string:entry);
        if(!isnull(item)) prelinked[item[1]] = TRUE;
      }
    }
  }

  var netstat_cmd = "netstat -anp";
  var ss_cmd = 'ss -anp';
  var netstat_buf = ldnix::run_cmd_template_wrapper(template:"LC_ALL=C "+netstat_cmd);
  var ss_buf;
  if (strlen(netstat_buf) == 0)
  {
    errmsg = ssh_cmd_error();
    if (errmsg) errmsg ='for the following reason :\n\n' + errmsg + '\n\n';
    else errmsg = 'for an unknown reason. ';
    errmsg = "Failed to run '" + netstat_cmd + "' " + errmsg;
    dbg::detailed_log(lvl:1, msg:errmsg);
  }
  if(!empty_or_null(netstat_buf))
  {
    set_kb_item(name:"Host/netstat_anp", value:netstat_buf);
    fill_socket_data(buf:netstat_buf, line_parser:@process_on_port_parser::parse_netstat_output_line);
  }
  else
  {
    ss_buf = ldnix::run_cmd_template_wrapper(template:"LC_ALL=C "+ss_cmd);
    if(strlen(ss_buf) == 0)
    {
      errmsg = ssh_cmd_error();
      if (errmsg) errmsg ='for the following reason :\n\n' + errmsg + '\n\n';
      else errmsg = 'for an unknown reason. ';
      errmsg = "Failed to run '" + ss_cmd + "' " + errmsg;
      dbg::detailed_log(lvl:1, msg:errmsg);
      
      if (info_t == INFO_SSH) ssh_close_connection();
      exit(1, "Both nestat and ss failed, see debug log for errors");
    }
  }
  if(!empty_or_null(ss_buf))
  {
    set_kb_item(name:"Host/ss_anp", value:ss_buf);
    fill_socket_data(buf:ss_buf, line_parser:@process_on_port_parser::parse_ss_output_line);
  }
}
# Suggested by Bernhard Thaler
#
# http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21264632
else if ("AIX" >< uname)
{
  netstat_cmd = "netstat -Aan";
  buf = info_send_cmd(cmd:"LC_ALL=C "+netstat_cmd);
  if (strlen(buf) == 0)
  {
    errmsg = ssh_cmd_error();
    if (errmsg) errmsg ='for the following reason :\n\n' + errmsg + '\n\n';
    else errmsg = 'for an unknown reason. ';
    errmsg = "Failed to run '" + netstat_cmd + "' " + errmsg;
    if (info_t == INFO_SSH) ssh_close_connection();
    exit(1, errmsg);
  }
  set_kb_item(name:"Host/netstat_Aan", value:buf);

  foreach line (split(buf, keep:FALSE))
  {
    v = pregmatch(string:line, pattern:'^(f[a-f0-9]{15})[ \t]+((tcp|udp)[46]?)[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+(\\*|[0-9]+\\.[0-9.]+\\.[0-9]+\\.[0-9]+)\\.([0-9]+)[ \t]+(\\*|[0-9]+\\.[0-9.]+\\.[0-9]+\\.[0-9]+)\\.[0-9*]+([ \t]+LISTEN)?$');
    if (isnull(v)) continue;

    port = int(v[5]);
    if (port < 0 || port > 65535) continue;

    proto = tolower(v[3]);
    if (proto != "tcp" && proto != "udp") continue;

    pcbaddr = v[1];

    exe = cmdline = '';

    cmd = "rmsock " + pcbaddr + " ";
    if (proto == "tcp") cmd += "tcpcb";
    else cmd += "inpcb";

    buf = info_send_cmd(cmd:"LC_ALL=C "+cmd + ' 2>/dev/null');
    if (strlen(buf) > 0)
    {
      buf = chomp(buf);
      v2 = pregmatch(string:buf, pattern:"The socket [^ ]+ is being held by proccess ([0-9]+)[ \t]+\(([^)]+)\)\.");
      if (!isnull(v2))
      {
        pid = int(v2[1]);
        exe = v2[2];

        cmd = "proctree " + pid;
        buf = info_send_cmd(cmd:"LC_ALL=C "+cmd+" 2>/dev/null");
        if (strlen(buf) > 0)
        {
          foreach line (split(buf, keep:FALSE))
          {
            v2 = pregmatch(pattern:'^[ \t]*'+pid+'[ \t]+([^ \t].+)$', string:line);
            if (!isnull(v2)) cmdline = v2[1];
          }
        }
      }
      else
      {
        v2 = pregmatch(string:buf, pattern:"The socket [^ ]+ is being held by Kernel/Kernel Extension\.");
        if (!isnull(v2))
        {
          pid = "n/a";
          exe = "[kernel/kernel extension]";
        }
      }
    }
    if (strlen(exe) == 0) continue;

    k = strcat(proto, '/', port);
    if (exes[k]) continue;

    localaddrs[k] = v[4];
    exes[k] = exe;
    if (pid > 0 || pid == "n/a") pids[k] = pid;
    if (strlen(cmdline) > 0) cmdlines[k] = cmdline;
  }
}
if (max_index(keys(exes)) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, "The host does not have any listening services.");
}


found = 0;
ip = get_host_ip();

foreach k (sort(keys(exes)))
{
  v = pregmatch(pattern:"^(.+)/([0-9]+)$", string:k);
  if (isnull(v))
  {
    if (info_t == INFO_SSH) ssh_close_connection();
    exit(1, "Failed to parse protocol / port info for '"+k+"'.");
  }

  proto = v[1];
  port = v[2];

  exe = exes[k];
  localaddr = localaddrs[k];
  cmdline = cmdlines[k];
  cmdline_enc = cmdlines_enc[k];
  if (strlen(cmdline) == 0) cmdline = "n/a";
  if (strlen(cmdline_enc) == 0) cmdline_enc = "n/a";
  pid = pids[k];

  set_kb_item(name:'Host/Daemons/'+localaddr+'/'+proto+'/'+port, value:exe);

  if (
    (
      TARGET_IS_IPV6 &&
      (localaddr == "::" || localaddr == ip)
    ) ||
    (
      !TARGET_IS_IPV6 &&
      (localaddr == '0.0.0.0' || localaddr == ip || localaddr == "::" || localaddr == "*")
    )
  )
  {
    set_kb_item(name: 'Host/Listeners/'+proto+'/'+port, value:exe);
    set_kb_item(name: 'Host/Listeners/'+proto+'/'+port+'/cmdline', value:cmdline_enc);
    set_kb_item(name: 'Host/Listeners/'+proto+'/'+port+'/pid', value:pid);

    found++;

    match = pregmatch(pattern:"^(.+) \(deleted\)$", string:exe);
    if (!isnull(match)) exe = match[1];

    if (exe[0] == '/') lead_slash = '';
    else lead_slash = '/';

    if(!isnull(md5s[pid]))
      replace_kb_item(name: 'Host/DaemonMD5s' + lead_slash + exe, value:md5s[pid]);

    # this is here so we only report on listening pre-linked daemons
    if(prelinked[exe])
    {
      # whitelist
      if(exe =~ "^[0-9A-Za-z_\-./]+$")
        buf = info_send_cmd(cmd:"prelink -y " + exe + " | md5sum");

      item = pregmatch(pattern:'^([a-zA-Z0-9]{32}) ', string: buf);
      if(!isnull(item))
        replace_kb_item(name: 'Host/PrelinkedDaemons' + lead_slash + exe, value:item[1]);
      else
        replace_kb_item(name: 'Host/PrelinkedDaemons' + lead_slash + exe, value:'md5_unknown');

    }
    report = '\n  Process ID   : ' + pid +
             '\n  Executable   : ' + exe;
    if (strlen(cmdline) > 0) report += '\n  Command line : ' + cmdline;
    report += '\n';
    if (COMMAND_LINE) report = '\n  Port         : ' + port + ' (' + proto + ')' + report;

    if (report_verbosity > 0) security_note(port:port, proto:proto, extra:report);
    else security_note(port:port, proto:proto);
  }
}
if (info_t == INFO_SSH) ssh_close_connection();
if (found) set_kb_item(name:"Host/Listeners/Check", value:netstat_cmd);
