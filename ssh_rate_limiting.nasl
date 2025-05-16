#TRUSTED 88a6c6ec6045b32aeb92c1be4f7069c8d43dc9054929f91843f63994647941df871f22c0536ad180b25256594498172b4886746456455199b48e4702a00bd82202262e32784e586d8eabca7fdf944946647ae121ee5b2c2e542c14196f6cf51431414237243d9fde1ea92cb39533ca5f215abd250db31ae2ed88bf3ead25db020c891a1d91aa67b0a1d7de08c09d37d634f32d58dc29a0cb5edc430f128c691f1576cc209547431ea41674e407400a7768d8929df7aef2647149d1f94a3ec94721ea1c8ff8604f6ce01dcefa87ab5f8180d8b39bd72c54fd09d436c5f009639526243839a5bbe5f517494c38af6f51a190498e572fc678ebca29c49e030a83794643ee9b82672b439bfd10de8efb8f53134b3aa761cf0c7d1867320517c9b6681a4faa66ffc607bc5972b9550d631d7f7777eaecd0fd6b66adb17a5328ec550294e1b00fe1ede6f231acff0e64dce599df54c7bc031876a89e2b353453e29170d58d74e60734b0e1e6409936ce2567788bf04e5fd9367be80d4c5f9d6aa7b5931669c169e1ef84ec2635494fbd2d49b54fe73c80eea3be4d3810a8a16fcc8c99a4206d68853974d9f2cd342346b39c776a3d5dafa33a5bc088bdc861a02233c15a8d91a270bad5379767d100d91a519247f8cc68fd2bd2d178166a40d6839bd7ea9e4f6ac358406c40de20c88ac1095f91be53c0291593caecb35e2eebcdb690
#TRUST-RSA-SHA256 9e2f2ef6305f17ec526e43cd413fa7c669e6ebf33bd590fdd2368eb408247289ddccae1a0708f978e5196f18e0392c3dfd7f55f51bd00f5937727de883d47096e5478d8119de6305874efbfd7f4a451b026c48cfe3ec9025e812e08a5210db4e71f382f8a4962d68849fb66e2c562ba648870be98a402c30541dbc9cb73f46d957bf2e855111c380958b2bd8e96e2b09fbd7c5df8e9c82d7266227bd26c4a1c634392700f93ca55dacd2296524e77bcc10533e9ed863bd4bc76bd66c93fbba9cb34af31b2f71396fd335762a25cc4026d2d4c1815e045e9f64c12c799a26907d24057556929ab815bba67890446ce9b2db8496d75b891812ccc35d1853411df90ce7ee54066c1ca2831798bbca83d674d9a5aa7cac9836b1f8b7b8fa19c11a68dca5b51ff05782f7332ccd1dba617f39e0a4ab17c10b6bf023c9720f232c3d156b04b2900e1aaec8b70965fb5d9ebc0a9d3676a94808dd76132e8207f07978ecb94bc36ffbb95706d473f8ea07045399d46b01ac7763b2920b4badd4c871e51433d13b53ad21ba53d974b185ce98d64d989d038903cde0bcbaec93e3456991c1d0c34707dfcd27624685e236b7a10bf2326fbc56880b91c2a32145fe968706c51222b61ad6a851a70c8b8b6404dd2b438f3c8981a2feaad2248546e8d8711d3f2e8a16d668f55d4e0c2e2143113dc5a2659126b48f5b8f234d41a7f995ae0aef
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122501);
  script_version("1.31");

  script_name(english:"SSH Rate Limited Device");
  script_summary(english:"Attempts to login to remote device and determine if SSH connections are rate limited.");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/03");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a SSH rate limited networking device that may
cause intermittent authentication failures throughout the scan.");
  script_set_attribute(attribute:"description", value:
"The remote host is a device that may rate limit connections,
potentially causing intermittent authentication failures in
other plugins.  Local checks will be enabled in this plugin
where possible.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/28");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_settings.nasl", "clrtxt_proto_settings.nasl", "ping_host.nasl");

  exit(0);
}

include("datetime.inc");
include("string.inc");
include("byte_func.inc");

include("ssh_func.inc");
include("ssh_lib.inc");
include("ssh_get_info2.inc");
include("agent.inc");
include("ssh_rate_limit.inc");
include("telnet_func.inc");
include("junos.inc");
include("structured_data.inc");

var FLATLINE_TEST = !isnull(get_kb_item("flatline/TEST"));

# should not be included in agent. disable here to be sure.
if(agent()) exit(0,"This plugin is disabled on Nessus Agents.");

start_time = gettimeofday();
enable_ssh_wrappers();

if(islocalhost())
{
  info_t = INFO_LOCAL;
}
else info_t = INFO_SSH;

# Check if port(s) are open; doing manual because port scanner
# have yet to run at this point in the scan.
# Build list of ssh_ports to try, preferred port should be first in list
var ssh_ports = make_list(22);
var pref_port = get_kb_item('Secret/SSH/PreferredPort');
var srl_socket = NULL;
var srl_at_least_one_port_open = FALSE;

if (pref_port)
  ssh_ports = make_list(pref_port, ssh_ports);

dbg::detailed_log(
  src:SCRIPT_NAME,
  lvl:2,
  msg:"Port list to attempt connections to : " + obj_rep(ssh_ports));

foreach var port (list_uniq(ssh_ports))
{
  dbg::detailed_log(src:SCRIPT_NAME, lvl:2, msg:"Connecting to port "+port+".");
  if (!FLATLINE_TEST)
    srl_socket = open_sock_tcp(port, timeout:3);
  else
    srl_socket = get_kb_item('flatline/srl_socket');

  if (srl_socket)
  {
    dbg::detailed_log(
      src:SCRIPT_NAME,
      lvl:2,
      msg:"Connection successfull on port "+port+". Not checking others.");
    close(srl_socket);
    srl_at_least_one_port_open = TRUE;
    break;
  }
  else
  {
    dbg::detailed_log(src:SCRIPT_NAME, lvl:2, msg:"Unable to connect to port "+port+".");
  }
}

if (!srl_at_least_one_port_open)
{
  dbg::detailed_log(
    src:SCRIPT_NAME,
    lvl:2,
    msg:"Unable to connect to at least one port. Exiting.");
  audit(AUDIT_NOT_LISTEN, 'Target', 'specified by policy for SSH','any');
}

var session = new("sshlib::session");
# disable compression
sshlib::KEX_SUPPORTED_NAME_LISTS["compression_algorithms_server_to_client"] = "none";
sshlib::KEX_SUPPORTED_NAME_LISTS["compression_algorithms_client_to_server"] = "none";

# login with placeholder value for channel. new_channel is passed by reference so it will be
# picked up later in plugin.

var channel = session.get_channel();
var sd_auth_info = new structured_data_authentication_status_information();
var login_res = sshlib::try_ssh_kb_settings_login(
  session          : session,
  accept_none_auth : TRUE,
  rate_limit       : TRUE,
  new_channel      : channel,
  force_none_auth  : TRUE,
  sd_auth_info     : sd_auth_info
);

delete(sd_auth_info);


if(!login_res)
{
  dbg::detailed_log(src:SCRIPT_NAME, lvl:1, msg:'Login via sshlib::try_ssh_kb_settings_login has failed.');

  # Removing the auth methods detected so that the next plugins can start fresh.
  var methods = get_kb_list(sshlib::SSH_LIB_KB_PREFIX + "*/supported_login_methods");
  for (var key in methods)
    rm_kb_item(name:key);

  # Remove the failure so that plugins down the chain can verify after service detection
  rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed");

  session.close_connection();
  audit(AUDIT_FN_FAIL, 'sshlib::try_ssh_kb_settings_login');
}


# determine authentication type from try_ssh_kb_settings_login
var sonicwall_none = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "sonicwall/none");
var sonicwall_password = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "sonicwall/passwordauth");
var junos_auth = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "junos/auth");
var juniper_ssr_auth = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "JuniperSSR/auth");
var omniswitch_auth = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "omniswitch/auth");

if(!sonicwall_none && !sonicwall_password && !junos_auth && !omniswitch_auth && !juniper_ssr_auth)
{
  session.close_connection();
  exit(0,"Device is not identified as a connection limited system.");
}

# sh shell handler set in try_ssh_kb_settings_login()
var sh = channel.shell_handler;
var timediff;

# sonicwall device
if(sonicwall_password || sonicwall_none)
{
  var report_no_command_sw;
  report_no_command_sw = "The remote host has been identified as a SonicWall or other" + '\n' +
                         "networking device that may be rate limiting SSH connections." + '\n';
  report_no_command_sw += "As a result there may be intermittent authentication failures" + '\n' +
                          "reported for this device." + '\n\n';
  report_no_command_sw += "Attempts to run commands to gather more information on" + '\n' +
                          "the device have failed." + '\n';
  # run commands on sonicwall device using sh shell handler 'raw' commands for limited shell handling functionality
  # sonicwall devices only have one login mode unlike junos which has a shell mode and cli mode
  var cmd_out = get_kb_item('flatline/sonic_sh_run_command');
  if(empty_or_null(cmd_out))
  {
    cmd_out = sh.run_command(channel:channel, command:"show device", raw:TRUE, cmd_timeout_min:60, sonicwall:TRUE);
    if(!check_command_output(data_buf:cmd_out))
      cmd_out = sh.run_command(channel         :channel,
                               command         :"show version", 
                               raw             :TRUE, 
                               cmd_timeout_min :60, 
                               sonicwall       :TRUE);
  }
  if(!check_command_output(data_buf:cmd_out))
  {
    # if failed to run commands exit without setting KB items - something went wrong.
    # legacy library will attempt to authenticate and run commands in ssh_get_info.nasl
    if(empty_or_null(cmd_out))
    {
      dbg::detailed_log(src:SCRIPT_NAME, lvl:1, msg:'Failed to run commands on SonicWall device: no data received after opening shell.');
    }
    else
    {
      dbg::detailed_log(
        src:SCRIPT_NAME,
        lvl:1,
        msg:'Failed to run commands on SonicWall device.',
        msg_details:{"Response":{"lvl":1, "value":cmd_out}});
    }
    session.close_connection();
    security_report_v4(
      port       : session.port,
      severity   : SECURITY_NOTE,
      extra      : report_no_command_sw
    );
    exit(0);
  }

  var os_name = "SonicOS";
  var up_time = "unknown";
  var edition = "unknown";
  var os_line, model_line, match;
  var uptime_line;
  var sonic_router = FALSE;

  # sonicwall < 6
  if("Firmware Version: SonicOS" >< cmd_out)
  {
    set_kb_item(name:"Host/SonicOS/show_device", value:cmd_out);
    write_compliance_kb_sonicwall(command:"show device", result:cmd_out);
    os_line = pgrep(pattern:"^Firmware Version:", string:cmd_out);
    if (os_line)
    {
      os_line = chomp(os_line);
      match = pregmatch(pattern:"^Firmware Version: SonicOS ((Enhanced|Standard) [0-9][^ ]+)", string:os_line);
      if (!isnull(match)) os_name += " " + match[1];
    }
    model_line = pgrep(pattern:"^Model:", string:cmd_out);
    if (model_line)
    {
      model_line = chomp(model_line);
      match = pregmatch(pattern:"^Model: (.+)", string:model_line);
      if (!isnull(match)) os_name += " on a SonicWALL " + match[1];
    }
    # Collect time of last reboot.
    if ("Up Time:" >< cmd_out)
    {
      foreach var line (split(cmd_out, keep:FALSE))
      {
        if (preg(pattern:"^Up Time: [0-9]", string:line))
        {
          up_time = line;
          break;
        }
      }
    }
  }
  # sonicwall 6 and 7
  else if('firmware-version "SonicOS' >< cmd_out)
  {
    if ('SonicOSX' >< cmd_out) os_name = 'SonicOSX';
    set_kb_item(name:"Host/SonicOS/show_version", value:cmd_out);
    write_compliance_kb_sonicwall(command:"show version", result:cmd_out);
    os_line = pgrep(pattern:'^firmware-version "', string:cmd_out);
    if (os_line)
    {
      os_line = chomp(os_line);
      var pattern = '^firmware-version "SonicOSX? ((Enhanced |Standard )?[0-9.]+(?:-[a-zA-Z0-9]+)?)';
      match = pregmatch(pattern:pattern, string:os_line);
      if (!isnull(match)) os_name += " " + match[1];
    }

    model_line = pgrep(pattern:'^model "', string:cmd_out);
    if (model_line)
    {
      model_line = chomp(model_line);
      match = pregmatch(pattern:'^model "(.+)"', string:model_line);
      if (!isnull(match)) os_name += " on a SonicWALL " + match[1];
    }
    # Collect time of last reboot.
    if (cmd_out && 'system-uptime "' >< cmd_out)
    {
      foreach line (split(cmd_out, keep:FALSE))
      {
        if (preg(pattern:'^system-uptime "', string:line))
        {
          up_time = line - 'system-uptime "' - '"'; 
          break;
        }
      }
    }
  }
  # SonicOS Router
  else if ('SONiC Software Version' >< cmd_out)
  {
    set_kb_item(name:"Host/SonicOS/show_version", value:cmd_out);
    os_line = pgrep(pattern:"^SONiC Software Version", string:cmd_out);
    if (os_line)
    {
      os_line = chomp(os_line);
      pattern = "Software\sVersion:\sSONiC\-OS\-([\d\.]+)[\s|-]?([\w]+|)";
      match = pregmatch(pattern:pattern, string:os_line);
      if (!isnull(match) && !isnull(match[1]))
      {
        if (!isnull(match[2]))
          edition = str_replace(string:match[2], find:"_", replace:" ");

        os_name += " " + match[1] + " " + edition;
        sonic_router = TRUE;
      }
    }
    model_line = pgrep(pattern:'^HwSKU', string:cmd_out);
    if (model_line)
    {
      model_line = chomp(model_line);
      match = pregmatch(pattern:"HwSKU:\s([\w-]+)", string:model_line);
      if (!isnull(match)) os_name += " on " + match[1];
    }
    # Collect time of last reboot
    uptime_line = pgrep(pattern:"^Uptime", string:cmd_out);
    if (uptime_line)
    {
      uptime_line = chomp(uptime_line);
      pattern = "\sup\s+([\d]+\s\w+|\d+\:\d\d)\,\s+";
      match = pregmatch(pattern:pattern, string:uptime_line);
      if (!empty_or_null(match) && !isnull(match[1]))
        up_time = match[1];
    }
  }
  else
  {
    if (!empty_or_null(cmd_out))
      report_no_command_sw += '\nThe output from "show device" or "show version":\n' + cmd_out;

    # report and exit that sonicwall detected but commands failed to run
    session.close_connection();
    security_report_v4(
      port       : session.port,
      severity   : SECURITY_NOTE,
      extra      : report_no_command_sw
    );
    exit(0);
  }

  # if we reach here sonicwall commands were successful
  set_kb_item(name:"Host/OS/showver", value:os_name);
  set_kb_item(name:"Host/OS/showver/Confidence", value:100);  
  set_kb_item(name:"Host/last_reboot", value:up_time);
  set_kb_item(name:"Host/OS/ratelimited_sonicwall", value:TRUE);
  if (sonic_router)
    set_kb_item(name:"Host/OS/showver/Type", value:"router");
  else
    set_kb_item(name:"Host/OS/showver/Type", value:"firewall");
  # set sshlib support level indicating local checks are not available
  set_support_level_na();

  var enable_sonicwall_compliance, report_compliance;

  if (strlen(get_preference("SonicWALL SonicOS Compliance Checks[file]:Policy file #1 :")) > 0)
  {
    enable_sonicwall_compliance = TRUE;
    # run commands for compliance checks - will be cached in KB.
    # run "show tech-support-report" command first and cache in KB so
    # other related commands can use that data.
    # This is a very long command output so increasing timeout.
    var tech_support_command = "show tech-support-report";
    cmd_out = sh.run_command(channel:channel, command:tech_support_command, raw:TRUE,
                            cmd_timeout_min:90, inactivity_timeout_min:75, sonicwall:TRUE);
    if(check_command_output(data_buf:cmd_out))
    {
      write_compliance_kb_sonicwall(command:tech_support_command ,result:cmd_out);
    }
    else cmd_out = "NA";
    run_sonicwall_commands_compliance(session:session, channel:channel, tsr_result: cmd_out);
  }

  report = "The remote host has has been identified as a SonicWall or other" + '\n' +
           "networking device that may be rate limiting SSH connections." + '\n';
  report += "As a result there may be intermittent authentication failures" + '\n' +
            "reported for this device." + '\n\n';

  report += "Although local, credentialed checks for SonicOS are not available," + '\n';
  if(enable_sonicwall_compliance) report_compliance = " and Policy Compliance plugins.";
  else report_compliance = ".";
  report += "Nessus has managed to run commands in support of " + '\n' +
            "OS fingerprinting" + report_compliance + '\n\n';

  report += 'Device information : ' + os_name + '\n';

  timediff = timeofday_diff(start:start_time, end:gettimeofday());
  report += '\nRuntime : ' + timediff + ' seconds\n';

  # close and report
  session.close_connection();
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}

# Junos device
# Note: the only escalation Junos devices support is 'su'.
#       Priv escalation is not supported in this plugin or the legacy ssh library.
#       If we encounter an insufficient priv message, report in plugin output and debug logs.
else if(junos_auth)
{
  var priv_error = FALSE;
  var in_shell_mode, k, cmd, raw_cmd, kb, output, login_buf;
  report = '\nThe remote host has has been identified as a Juniper Junos' +
           '\ndevice that may be SSH rate limited.\n';
  report += 'As a result there may be intermittent authentication failures' +
            '\nreported for this device.\n';
  # We need to close the session using the shell handler before we can run exec commands
  # Commands run in exec mode to avoid cleaning up the command outputs
  dbg::detailed_log(src:SCRIPT_NAME, lvl:3, msg:'Closing previous channel to allow exec commands to open their own.');
  if (!FLATLINE_TEST && !isnull(channel))
    channel.close();

  var commands_ssh_get_info = make_array(
    'version', 'show version detail',
    'last', 'show chassis routing-engine',
    'config', 'show configuration | display set',
    'interface', 'show interface'
  );
  var cmd_results = make_array();

  if(get_kb_item("Host/Juniper/JUNOS/shell"))
    in_shell_mode = TRUE;
  # run commands to enable local checks
  foreach k (keys(commands_ssh_get_info))
  {
    cmd = commands_ssh_get_info[k];
    raw_cmd = cmd;
    kb = str_replace(string:cmd, find:" ", replace:"_");
    kb = str_replace(string:kb, find:"/", replace:"");
    kb = "Host/Juniper/JUNOS/Config/" + kb;
    cmd += " | no-more";

    cmd = junos_format_cmd(cmd: cmd, flag: in_shell_mode);

    dbg::detailed_log(
      src:SCRIPT_NAME,
      lvl:2,
      msg:'Running the following command.',
      msg_details:{
        "Command": {"lvl":2, "value":cmd},
        "In shell mode?": {"lvl":2, "value":in_shell_mode}});

    output = get_kb_item('flatline/junos_sh_run_command/' + k);
    if(empty_or_null(output))
      output = session.run_exec_command(command:cmd); 

    #output may be different with FIPS mode enabled
    if(k == 'version' && 'Invalid argument' >< output)
    {
      dbg::detailed_log(
        src:SCRIPT_NAME,
        lvl:3,
        msg:'The command failed with the following response. Retrying with local.',
        msg_details:{
          "Command": {"lvl":3, "value":cmd},
          "Response": {"lvl":3, "value":output}});
      cmd = 'show version local detail | no-more';
      cmd = junos_format_cmd(cmd: cmd, flag: in_shell_mode);
      dbg::detailed_log(
        src:SCRIPT_NAME,
        lvl:3,
        msg:'Running the following command.',
        msg_details:{"Command": {"lvl":3, "value":cmd}});

      output = get_kb_item('flatline/junos_sh_run_command/fips');
      if(empty_or_null(output))
        output = session.run_exec_command(command:cmd);
    }
    if("/* ACCESS-DENIED */" >< output)
    {
      dbg::detailed_log(
        src:SCRIPT_NAME,
        lvl:1,
        msg:'The command failed with the following response due to user privilege error.',
        msg_details:{
          "Command": {"lvl":1, "value":cmd},
          "Response": {"lvl":1, "value":output}});
      output = FALSE;
      priv_error = TRUE;
    }
    else if(!check_command_output_junos(data_buf:output))
    {
      dbg::detailed_log(
        src:SCRIPT_NAME,
        lvl:1,
        msg:'The command failed with the following response.',
        msg_details:{
          "Command": {"lvl":1, "value":cmd},
          "Response": {"lvl":1, "value":output}});
      output = FALSE;
    }
    if(output)
    {
      set_kb_item(name:"Secret/"+kb, value:output);
      write_compliance_kb_junos(command:raw_cmd, result:output);
    }
    cmd_results[k] = output;
    sleep(1);
  }

  var version = cmd_results["version"];
  var last = cmd_results["last"];
  var config = cmd_results["config"];
  var interface = cmd_results["interface"];

  # try to retrieve the list of installed packages
  if(in_shell_mode)
  {
    var pkginfo_cmd = "/usr/sbin/pkg_info -a";
    dbg::detailed_log(
      src:SCRIPT_NAME,
      lvl:2,
      msg:'Running the following command (in shell mode).',
      msg_details:{"Command": {"lvl":2, "value":pkginfo_cmd}});
    var buf = session.run_exec_command(command: pkginfo_cmd);
    var pkg_info_success = TRUE;

    if (!buf)
    {
      if ("no packages installed" >< session.cmd_error)
        buf = ' ';
      else
      {
        report += 'Command \''+pkginfo_cmd+'\'failed to produce any results.';
        pkg_info_success = FALSE;
      }
    }
    if (pkg_info_success)
    {
      buf = str_replace(find:'\t', replace:"  ", string:buf);
      replace_kb_item(name:"Host/JunOS/pkg_info", value:buf);
    }
  }

  var set_last_reboot, last_reboot_value;
  var os_ver = "";

  # Parse the version from the 'show version detail' output
  if(!empty_or_null(version))
  {
    # Match "JUNOS Software Release [18.4R2-S7.4]" or "JUNOS EX  Software Suite [18.4R2-S7.4]"
    # or just "Junos: 21.2R3-S3.5" for models like srx1500
    os_ver = pregmatch(pattern:"JUNOS\s+(?:EX\s+)?Software\s+(?:Release|Suite)\s+\[([^\]]+)\]", string:version);
    if (empty_or_null(os_ver))
      os_ver = pregmatch(pattern:"Junos: (\d[^\s]+)", string:version);

    if (!empty_or_null(os_ver) && !isnull(os_ver[1]))
      os_ver = " Version " + os_ver[1];
  }

  # Get time of last reboot.
  if (last)
  {
    foreach line (split(last, keep:FALSE))
    {
      match = pregmatch(pattern:"Start time[ \t]+(.+)$", string:line);
      if (match)
      {
        set_last_reboot = TRUE;
        last_reboot_value = match[1];
        break;
      }
    }
  }

  if (config)
  {
    kb = "Secret/Host/Juniper/JUNOS/config/show_configuration_|_display_set";
    replace_kb_item(name:kb, value:config);
  }

  get_junos_mac_addrs(session:session, channel:channel, cmd_result:interface);
  if(version && ("Hostname" >< version || "JUNOS" >< version))
  {
    set_kb_item(name:"Host/Juniper/show_ver", value:version);
    set_kb_item(name:"Host/OS/ratelimited_junos", value:TRUE);
    report += '\nLocal security checks have been enabled for Juniper Junos.\n';

    # if local checks are enabled run commands for junos_command_kb_item in junos_kb_cmd_func.inc
    dbg::detailed_log(src:SCRIPT_NAME, lvl:2, msg:"Junos local checks are enabled. Running commands used by junos_command_kb_item().");
    run_junos_command_kb_item(session:session, shell:in_shell_mode);
    # set sshlib service level for junos local checks
    sshlib::enable_local_checks();
    replace_kb_item(name:'debug/Host/local_checks_enabled_source/plugins/Misc/s/ssh_rate_limiting.nasl', value: 539);

    replace_kb_item(name:"Host/OS/showver", value:"Juniper Junos" + os_ver);
    replace_kb_item(name:"Host/OS/showver/Confidence", value:100);
    replace_kb_item(name:"Host/OS/showver/Type", value:"embedded");
    if(set_last_reboot)
    {
      replace_kb_item(name:"Host/last_reboot", value:last_reboot_value);
    }
  }
  else
  {
    login_buf = tolower(get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "junos_prompt"));
    # Making sure the device is really a Junos before disabling local checks
    if (!empty_or_null(login_buf) && login_buf =~ "junos\s+\d+\.[\d\w\.]+")
    {
      set_support_level_na();
      set_kb_item(name:"Host/OS/ratelimited_junos", value:TRUE);
      set_kb_item(name:"Host/OS/ratelimited_junos_error", value:TRUE);
    }
    timediff = timeofday_diff(start:start_time, end:gettimeofday());
    report += '\nJunos device detected, however, some commands failed to run\n' +
              'so local checks are not enabled.\n';
    if(priv_error)
      report += '\nAuthentication successful, however, some commands' +
                '\nfailed to run due to insufficient user privileges.\n';
    report += '\nRuntime : ' + timediff + ' seconds\n';
    session.close_connection();
    security_report_v4(
      port       : session.port,
      severity   : SECURITY_NOTE,
      extra      : report
      );
    exit(0);
  }

  if(priv_error)
  {
    report += '\nAuthentication successful and local checks enabled, however, some' +
              '\ncommands failed to run due to insufficient user privileges.\n';
  }
  timediff = timeofday_diff(start:start_time, end:gettimeofday());
  report += '\nRuntime : ' + timediff + ' seconds\n';

  # close and report
  session.close_connection();
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}

else if (juniper_ssr_auth)
{
  report = 
    '\nThe remote host has has been identified as a Juniper SSR' +
    '\ndevice that may be SSH rate limited.\n' +
    'As a result there may be intermittent authentication failures' +
    '\nreported for this device.\n';

  var in_PCLI = FALSE;
  var logged_as_PCLI = FALSE;
  if (get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "JuniperSSR/is_PCLI"))
  {
    in_PCLI = TRUE;
    logged_as_PCLI = TRUE;
  }

  var kb_prefix = 'Host/JuniperSSR/';
  var commands = [
    {
      cmd          : 'show system version',
      require_PCLI : TRUE,
      kb           : kb_prefix + 'show_system_version',
      cmd_rgx      : "\s*Router\s+Node\s+Version\s+Build Date\s+Package"
    },
    # The following cmd_rgx matches column headers 'Admin Status', 'Operational Status', 'Provisional Status', 'Redundancy Status', 'MAC Address' which may be truncated
    {
      cmd          : 'show device-interface summary',
      require_PCLI : TRUE,
      kb           : kb_prefix + 'show_device_interface_summary',
      cmd_rgx      : "\s*Admin.+Oper.+Prov.+Red.+MAC|Keyword argument 'router' is required|No device interfaces to display"
    }
  ];

  var command_successful = FALSE;
  var failed_cmds = [];
  var cmd_output;
  for (var cmd_info of commands)
  {
    if (!in_PCLI && cmd_info.require_PCLI)
    {
      dbg::detailed_log(
        lvl:2,
        msg:'Could not run the command as the user is not in PCLI mode.',
        msg_details:{
          'Command':{lvl:2, value:cmd_info.cmd}
        }
      );
      continue;
    }
    if (logged_as_PCLI && !cmd_info.require_PCLI)
    {
      dbg::detailed_log(
        lvl:2,
        msg:'Could not run the command as the non-escalated user is already in PCLI mode.',
        msg_details:{
          'Command':{lvl:2, value:cmd_info.cmd}
        }
      );
      continue;
    }

    if (!FLATLINE_TEST)
      cmd_output = sh.run_command(command:cmd_info.cmd, channel:channel, cmd_timeout_min:60, raw:TRUE);
    else
      cmd_output = get_kb_item('flatline/' + cmd_info.kb);

    if (cmd_info.cmd_rgx && cmd_output !~ cmd_info.cmd_rgx)
    {
      dbg::detailed_log(
        lvl:1,
        msg:'The command produced unexpected results.',
        msg_details:{
          'Command':{lvl:1, value:cmd_info.cmd},
          'Data':{lvl:3, value:cmd_output}
        }
      );
      append_element(var:failed_cmds, value:cmd_info.cmd);
      continue;
    }

    command_successful = TRUE;
    set_kb_item(name:cmd_info.kb, value:cmd_output);
  }

  if (command_successful && empty(failed_cmds))
  {
    report += '\nLocal checks have been enabled for the Juniper SSR device.\n';
    report += '\nOS Security Patch Assessment is available for Juniper SSR devices.\n';

    sshlib::enable_local_checks();
    replace_kb_item(name:'debug/Host/local_checks_enabled_source/plugins/Misc/s/ssh_rate_limiting.nasl', value: 683);
  }
  else
  {
    # Set support level to prevent other plugin from trying to run other commands.
    sshlib::set_support_level(level:sshlib::SSH_LIB_LOCAL_CHECKS_ERROR);
    set_kb_item(name:kb_prefix + 'error', value:TRUE);
    report += 
      '\nWe are able to identify the remote host as a Juniper SSR device, but encountered an error.'+
      '\nOS Security Patch Assessment is NOT available.\n';
    if (!empty(failed_cmds))
    {
      report += '\nThe following commands produced unexpected results:\n  - ';
      report += join(failed_cmds, sep:'\n  - ');
      report += '\n';
    }
  }

  if (!FLATLINE_TEST && logged_as_PCLI)
    sh.run_command(command:'quit', channel:channel, cmd_timeout_min:60, raw:TRUE);
  else if (!FLATLINE_TEST)
  {
    if (in_PCLI)
      sh.run_command(command:'quit', channel:channel, cmd_timeout_min:60, raw:TRUE);
    
    sh.run_command(command:'exit', channel:channel, cmd_timeout_min:60, raw:TRUE);
  }
  session.close_connection();

  set_kb_item(name:'Host/OS/show_system_version', value:'Juniper SSR');
  set_kb_item(name:'Host/OS/show_system_version/Confidence', value:100);
  set_kb_item(name:'Host/OS/show_system_version/Type', value:'router');
  set_kb_item(name:"Host/OS/ratelimited_JuniperSSR", value:TRUE);
  timediff = timeofday_diff(start:start_time, end:gettimeofday());
  report += '\nRuntime : ' + timediff + ' seconds\n';

  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}

#Alcatel-Lucent OmniSwitch
else if(omniswitch_auth)
{
  report = '\nThe remote host has been identified as an Alcatel-Lucent' +
           '\nOmniSwitch device that may be SSH rate limited.\n';
  report += 'As a result there may be intermittent authentication failures' +
            '\nreported for this device.\n';

  timediff = timeofday_diff(start:start_time, end:gettimeofday());
  report += '\nRuntime : ' + timediff + ' seconds\n';

  cmd = "show microcode";

  dbg::detailed_log(
    src:SCRIPT_NAME,
    lvl:2,
    msg:'Running the following command.',
    msg_details:{"Command": {"lvl":2, "value":cmd}});

  output = get_kb_item('flatline/omniswitch_sh_run_command/show_microcode');
  if(!FLATLINE_TEST && empty_or_null(output))
    output = sh.run_command(command:cmd, channel:channel, cmd_timeout_min:60, raw:TRUE);
  dbg::detailed_log(
    src:SCRIPT_NAME,
    lvl:3,
    msg:'The command returned with the following response.',
    msg_details:{
      "Command": {"lvl":3, "value":cmd},
      "Response": {"lvl":3, "value":output}});

  if(output =~ "Package\s*Release\s*Size\s*Description")
  {
    report += '\nLocal checks have been enabled for an Alcatel-Lucent OmniSwitch.\n';
    report += '\nOS Security Patch Assessment is not supported for Alcatel-Lucent OmniSwitch devices.\n';
    set_kb_item(name:"Host/AOS/show_microcode", value:output);
    set_kb_item(name:"Host/OS/ratelimited_omniswitch", value:TRUE);
  }
  else
  {
    dbg::detailed_log(
      src:SCRIPT_NAME,
      lvl:1,
      msg:'The command failed with the following error.',
      msg_details:{
        "Command": {"lvl":1, "value":cmd},
        "Error": {"lvl":1, "value":session.cmd_error}});
    report += 'However, running ' + serialize(cmd) + ' failed to produce expected results.';
  }

  # close and report
  if(!FLATLINE_TEST)
    sh.run_command(command:"exit", channel:channel, cmd_timeout_min:60, raw:TRUE);

  session.close_connection();
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}
else
{
  # should not reach
  session.close_connection();
  exit(0,"Unable to determine if remote host is a rate limited device.");
}



