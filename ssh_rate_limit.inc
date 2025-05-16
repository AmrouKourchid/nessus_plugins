#TRUSTED 2ae900ef5123bbd8db137cf6acebc6242821ad664686534bb7fd2a478332117aaff00aa2134a5f3980d44c4b06e3bdd716b1e8540ab0aa8ef5ca291f1cad76f10a8130dd207590acfd2007abb3ce28c4cd547364ddf4703e0a5af573cd6cc0bd43ef417037d7b4440338a71c99b6a37973e6e17d6740c7b62f89381566a33c686c7de824440c4b7c39fe7dfcb73735644beaebf632d9f1778518c01efbdc1fa773e7b771ff609053800e62609f963e0705379df2ca7e0b6963117ebaf95afd3d3d3cd6e24f55b9ee02b2c66e0f847d3806bb4635815dc34f0d821ac4691bdeaca31d075c3134d7bf1db5d29e062428fdd294a4f9da9decd1b452ea2a04311e6a9975d285c208386e65ebb708166244027ce4a4090833359b5eee78b733f288af657ee54c88d134209f7619fc4a5d233ba093291f5ce00a0cd110c0d9aed0fc048fc9451c5fc67649eadb6cf236c67e2d9c73ea8265feaa965dbe845070da0665680fd36e137709296dd04dc3121d3ac5ae1620ed5f6aa2ee5e63c3da158f11c67773588af54c08357fe7fae862be8e674fe5381a2dffb0a6e63137decddd0f11aab6bd811bdcaaec3cc00a2147bdcc9447a690da66447a1b4c422a406493330a376966ecafd745ad35e9526f2aed696c1bf39667a4bdac725f8678175e85eaf0067349c71ebb2191156ef2fdc2e326935a7c3a59ba206ff6c57273a107f45506
#TRUST-RSA-SHA256 8cdf321a23af7777fcf1174b73ffe7861acd5a4072c3443ece3707df72fa21ff9e0fff570442396c1bfe1ff4ad92399b2513d880c6942e33f53b369136f3a3135057920dc45ac13ece31a7cb45a66ac72545a9852ec9b42cf07c1f7cc80a72b6e075b3c5699983593052060c5f0b3732c5686f6fdcfac5c0c75f5c7949379b69bf24704b44b0eb68e03cfb62a01df8c9a0768a0c6b82c31e7500f5bf21a3fd0e03a9693cd4deeee2d4f91fa4293ac8f6825a08ebc95b441926300bcd6e169c8a643f136e4445bda3308144cb5b2dffc9ceb416d9c17db348dfa196a767f2fc45f1245c61e2be5cf45477615baed00459f5d09f74c60c532b997069f83b830927ed01a4e097adf9bb36acd1eb8128e6c597447b722e906a46c038ca1621238cb666d277afa82a41dac5a6fa505c04f8a76b919cf32ae79c073858b80d9e2e9b41a74a76dba004e3d316b2e1105250f54c76edf3d57ab68fc7f203b865aaecff14bbf3f6797a758ebf535e177f826187bf59ff8c69bfe15bddf6f39e51e0b41ca82a7a86611cb46177f00a32dc28831c016576a3b0b9820e136fcf59815c56bd7fb27b7b50a07941b0c6bccda6ed4e81ad58454b19d65b70e952d5d9e0f162ca5460694373cc6bc952ceb55f69bc73296b8ed076eb204edf34c0a55f9bb945264fbb05a05a7342da4422d67ae07da2ce21669ed801316f89538456ed0427eb0ade
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# Revision: 1.6
###

include("compat_shared.inc");
include("debug.inc");
include("ssh_lib.inc");
include("junos.inc");

# Functions used in ssh_rate_limiting.nasl
##
# Return master list of junos commands
#
# @return Returns list of junos commands
# @category SSH
##
function get_junos_commands()
{
  local_var junos_commands_list;
  # do not need to include 'no-more' this will be automatically added
  # duplicates will be ignored as commands are cached in KB
  junos_commands_list = ["show bgp neighbor",
                 "show bgp summary",
                 "show chassis cluster statistics",
                 "show chassis hardware",
                 "show chassis hardware extensive",
                 "show configuration",
                 "show configuration | display set",
                 "show interfaces",
                 "show ldp statistics",
                 "show rip neighbor",
                 "show route instance detail",
                 "show security alg status",
                 "show security utm web-filtering status",
                 "show services user-identification active-directory-access domain-controller status extensive",
                 "show system processes",
                 "show version detail | match 64",
                 "show vpls connections",
                 "show mpls interface",
                 # Compliance commands
                 'show version',
                 'show configuration system services | find "ssh" | match "macs"',
                 'show configuration system services | find "ssh" | match "ciphers"',
                 'show configuration interfaces | match "lo[0-9]"',
                 'show vrrp detail | match "Authentication type: md5"',
                 'show bgp neighbor | match "Authentication key is configured"',
                 'show bgp group',
                 'show configuration protocols | match "authentication" | except "loose"',
                 'show configuration system ntp | match "server" | except "boot-server"'
          ];
  return junos_commands_list;
}

##
# Return master list of sonicwall commands
#
# @return Returns list of sonicwall commands
# @category SSH
##
function get_sonicos_commands()
{
  local_var sonicos_commands_list;
  # duplicates will be ignored
  sonicos_commands_list = ["show version",
                   "show tech-support-report",
                   "show tech-support-report radius",
                   "show tech-support-report ldap",
                   "show tech-support-report management",
                   "show tech-support-report administration",
                   "show tech-support-report status",
                   "show tech-support-report update",
                   "show interfaces",
                   "show tech-support-report snmp",
                   "show tech-support-report users-settings",
                   "show tech-support-report network",
                   "show tech-support-report stateful-stats",
                   "show tech-support-report ssl-control",
                   "show tech-support-report intrusion-detection-prevention",
                   "show tech-support-report anti-virus",
                   "show tech-support-report gateway-anti-virus",
                   "show zone LAN",
                   "show zone WAN",
                   "show zone DMZ",
                   "show zone WLAN",
                   "show tsr all",
                   "show tsr radius",
                   "show tsr ldap",
                   "show tsr users",
                   "show tsr av",
                   "show tsr log",
                   "show tsr update",
                   "show tsr management",
                   "show interface all",
                   "show tsr snmp",
                   "show device",
                   "show tsr network",
                   "show tsr stateful-stats",
                   "show tsr ssl-control",
                   "show tsr idp",
                   "show tsr gav",
                   "show current-config"
              ];
  return sonicos_commands_list;
}

##
# Write compliance commands for SonicWall in KB so that compliance checks can use results.
#
# @param command  command to store in KB name
# @param result   command result to store in KB value
# @return Returns TRUE
# @category SSH
##
function write_compliance_kb_sonicwall(command,result)
{
  local_var cmd_no_spaces, cmd_no_spaces_lower, cmd_no_spaces_original;
  local_var command_lower, command_original;
  # compliance audits use a combination of capitalized and lowercase letters for the same commands
  # this creates unnecessary traffic to the host.
  # In the case of "show zone" commands store both versions in KB so compliance checks see it.
  # Example: "show zone wlan" vs "show zone WLAN"
  if("show zone" >< command)
  {
    command_lower = tolower(command);
    command_original = command;
    cmd_no_spaces_lower = str_replace(find: " ", replace: "_", string: command_lower);
    cmd_no_spaces_original = str_replace(find: " ", replace: "_", string: command_original);
    replace_kb_item(name:"Host/SonicWALL/"+cmd_no_spaces_lower, value: result);
    replace_kb_item(name:"Host/SonicWALL/"+cmd_no_spaces_original, value: result);
  }
  else
  {
    cmd_no_spaces = str_replace(find: " ", replace: "_", string: tolower(command));
    replace_kb_item(name:"Host/SonicWALL/"+cmd_no_spaces, value: result);
  }
}

##
# Run sonicwall commands to support compliance checks. Cache in KB.
#
# @param session  sshlib::session object
# @param channel  sshlib::channel object
# @param tsr_result command output of 'show tech-support-report'
#
# @return Returns TRUE
# @category SSH
##
function run_sonicwall_commands_compliance(session, channel, tsr_result)
{
  local_var cmd, res, buf, cmd_no_spaces, sh, fn;
  fn = "run_sonicwall_commands_compliance";
  # sh shell handler set in try_ssh_kb_settings_login()
  sh = channel.shell_handler;

  dbg::detailed_log(lvl:1, src:fn, msg:'running commands to support SonicWall compliance checks.');
  foreach cmd (get_sonicos_commands())
  {
    if(isnull(cmd)) continue;
    # parse command result sections for 'show tech-support-report $type' commands
    # 'show tech-suppor-report' root command is run before this function is called.
    # command result is cached in the KB so this function does not have to run the sub command
    parse_sonicwall_compliance_commands(session:session, cmd:cmd, result:tsr_result);
    cmd_no_spaces = str_replace(find: " ", replace: "_", string: cmd);
    buf = get_kb_item("Host/SonicWALL/" + tolower(cmd_no_spaces));
    if(!isnull(buf))
    {
      dbg::detailed_log(lvl:2, src:fn, msg:'command [' + cmd + '] already found in KB.');
      continue;
    }
    res = sh.run_command(channel:channel, command:cmd, raw:TRUE, cmd_timeout_min:75, sonicwall:TRUE);
    if(check_command_output(data_buf:res))
    {
      # cache correct command
      write_compliance_kb_sonicwall(command:cmd ,result:res);
    }
    else
    {
      # cache failure result so compliance plugin does not have to re-run it
      if(isnull(res))
        res = "no SSH command output";
      write_compliance_kb_sonicwall(command:cmd ,result:res);
      dbg::detailed_log(lvl:1, src:fn, msg:'running command [' + cmd + '] failed.');
    }
    sleep(4);
  }
  dbg::detailed_log(lvl:1, src:fn, msg:'done running SonicWall compliance commands.');
}

##
# Parse sonicwall commands for 'show tech-support-report' and cache
# sections in KB under sub command name.
# Runs in run_sonicwall_commands_compliance() and prevents 'show tech-support-report' sub commands
# from running.
#
# @param cmd command
# @param result result output
# @return Returns TRUE if result is found
# @category SSH
##
function parse_sonicwall_compliance_commands(session, cmd, result)
{

  local_var cmd_regex, regex_mappings, matches, command_to_match, matches_result, fn;
  local_var str, res_section, idx_end, matches_result_end;

  fn = "parse_sonicwall_compliance_commands";
  if(result == "NA") return FALSE; # if 'show tech-support-report' command did not work
                                   # break out of function and run the commands directly.
  if(isnull(result)) return FALSE;
  if(isnull(cmd)) return FALSE;

  regex_mappings = {};
  regex_mappings['radius']['start'] = "#Users : RADIUS_START";
  regex_mappings['radius']['end'] = "#Users : RADIUS_END";
  regex_mappings['ldap']['start'] = "#Users : LDAP_START";
  regex_mappings['ldap']['end'] = "#Users : LDAP_END";
  regex_mappings['management']['start'] = "#System : Administration_START";
  regex_mappings['management']['end'] = "#System : Administration_END";
  regex_mappings['administration']['start'] = "#System : Administration_START";
  regex_mappings['administration']['end'] = "#System : Administration_END";
  regex_mappings['status']['start'] = "#System : Status_START";
  regex_mappings['status']['end'] = "#System : Status_END";
  regex_mappings['update']['start'] = "#System : Settings_START";
  regex_mappings['update']['end'] = "#System : Settings_END";
  regex_mappings['snmp']['start'] = "#System : SNMP_START";
  regex_mappings['snmp']['end'] = "#System : SNMP_END";
  regex_mappings['users-settings']['start'] = "#Users : Settings_START";
  regex_mappings['users-settings']['end'] = "#Users : Settings_END";
  regex_mappings['network']['start'] = "#Firewall Settings : Advanced_START";
  regex_mappings['network']['end'] = "#Firewall Settings : Advanced_END";
  regex_mappings['stateful-stats']['start'] = "=======Misc : Stateful Stats=======";
  regex_mappings['stateful-stats']['end'] = "=======Misc : VxNet Debug=======";
  regex_mappings['ssl-control']['start'] = "#Firewall Settings : SSL Control_START";
  regex_mappings['ssl-control']['end'] = "#Firewall Settings : SSL Control_END";
  regex_mappings['intrusion-detection-prevention']['start'] = "#Security Services : Intrusion Prevention_START";
  regex_mappings['intrusion-detection-prevention']['end'] = "#Security Services : Intrusion Prevention_END";
  # 'show tech-support-report anti-virus' command ignored because it has multiple sections and no standard section markers
  regex_mappings['gateway-anti-virus']['start'] = "#Security Services : Gateway Anti-Virus_START";
  regex_mappings['gateway-anti-virus']['end'] = "#Security Services : Gateway Anti-Virus_END";

  cmd_regex = "show tech-support-report ([A-Za-z].*)";
  matches = pregmatch(pattern:cmd_regex, string:cmd);
  if(!empty_or_null(matches) && !isnull(matches[1]))
  {
    command_to_match = matches[1];
    dbg::detailed_log(lvl:3, src:fn, msg:'Finding section for: ' + command_to_match);
    matches_result = pgrep(pattern:regex_mappings[command_to_match]['start'], string:result);
    matches_result_end = pgrep(pattern:regex_mappings[command_to_match]['end'], string:result);
    if (!empty_or_null(matches_result) && !empty_or_null(matches_result_end))
    {
      str = strstr(result, matches_result);
      idx_end = stridx(str, regex_mappings[command_to_match]['end']);
      res_section = substr(str, 0, idx_end);
      if(!empty_or_null(res_section))
      {
        dbg::detailed_log(lvl:3, src:fn, msg:'Found section for : [ ' + cmd + ' ]');
        dbg::detailed_log(lvl:3, src:fn, msg:'Result : [ ' + res_section + ' ]');
        # write section result to KB under the command name (example: 'show tech-support-report radius')
        # if the section is not available do not write anything, return immediatley, and run the command direct.
        write_compliance_kb_sonicwall(command:cmd ,result:res_section);
        return TRUE;
      }
      else return FALSE;
    }
    else return FALSE;
  }
  else return FALSE;
}

##
# Write compliance commands for Juniper Junos in KB so that compliance checks can use results.
#
# @param command  command to store in KB name
# @param result   command result to store in KB value
# @return Returns TRUE
# @category SSH
##
function write_compliance_kb_junos(command, result)
{
  local_var cmd_no_spaces;
  cmd_no_spaces = str_replace(find:" ", replace:"_", string:command);
  replace_kb_item(name:"Host/Juniper/"+cmd_no_spaces, value:result);
}

##
# Check output of SonicWAll commands for failed command.
#
# @param data_buf  command result to check
# @return Returns TRUE if command succeeded.
# @category SSH
##
function check_command_output(data_buf)
{
  data_buf = tolower(data_buf);
  if("error encountered at '^' marker" >< data_buf || "no matching command" >< data_buf || "no such command" >< data_buf)
    return FALSE;
  else if(empty_or_null(data_buf))
    return FALSE;
  else
    return TRUE;
}

##
# Check output of Juniper Junos commands for failed command.
#
# @param data_buf  command result to check
# @return Returns TRUE if command succeeded.
# @category SSH
##
function check_command_output_junos(data_buf)
{
  if(empty_or_null(data_buf))
    return FALSE;
  else if("unknown command" >< tolower(data_buf))
    return FALSE;
  else if("syntax error, expecting" >< tolower(data_buf))
    return FALSE;
  else if("error: command is not valid" >< tolower(data_buf))
    return FALSE;
  else
    return TRUE;

}


##
# Set sshlib support level to indicate local checks not available
#
# @category SSH
##
function set_support_level_na()
{
  sshlib::set_support_level(level: sshlib::SSH_LIB_LOCAL_CHECKS_UNAVAILABLE);
  # set HostLevelChecks KB item for hostlevel_checks_unavailable.nasl
  set_kb_item(name:"HostLevelChecks/unavailable", value:SCRIPT_NAME);
}


##
# Function to get Junos mac addresses and save them in KB for other plugins
#
# @param session sshlib::session object
# @param channel sshlib::channel object
# @param cmd_result Result output of command that was already run against host.
# @category SSH
##
function get_junos_mac_addrs(session, channel, cmd_result)
{
  local_var ifconmac = "(([a-f0-9A-F]{2}[:-]){5}[a-f0-9A-F]{2})";
  # Most common command and pattern
  # running command "show interface | no-more"
  local_var regex    = "Hardware address: "+ifconmac;
  # Some temps for processing
  local_var line     = NULL;
  local_var infbuf   = NULL;
  local_var macs     = make_array();
  local_var matches  = NULL;
  local_var mlist    = "";

  if(isnull(cmd_result)) return FALSE;

  infbuf = cmd_result;
  infbuf = split(infbuf, sep:'\n', keep:FALSE);
  foreach line (infbuf)
  {
    matches = pregmatch(string:line, pattern:regex);
    if(!isnull(matches) && max_index(matches) > 1) 
      macs[matches[1]] = TRUE;
  }
  foreach line (keys(macs))
    mlist += line+',';
  mlist = ereg_replace(string:mlist, pattern:",$", replace:"");
  replace_kb_item(name:"Host/raw_macs", value:mlist);

  return TRUE;
}

##
# Run Juniper Junos commands to support local checks and compliance checks. Cache in KB.
#
# @param session      sshlib::session object
# @param no_more      append '| no-more' to command to disable pagination on command output (optional, default to TRUE)
# @param sleep_value  set sleep value in between commands (optional, default to 5)
# @return Returns TRUE
# @category SSH
##
function run_junos_command_kb_item(&session, shell, no_more, sleep_value)
{
  var cmd, output, buf, raw_cmd, local_commands_list, kb;
  var fn = 'run_junos_command_kb_item';

  if(isnull(sleep_value)) sleep_value = 5;
  # 'no-more' is not really needed since the exec method is used to run the commands
  # but it's safer to keep it
  if(isnull(no_more)) no_more = TRUE;
  # If shell option is used enforce no_more use for safety
  # If no-more is forgotten it can potentially write files to the device.
  if(shell) no_more = TRUE;
  # if compliance checks are enabled then run both sets of commands
  local_commands_list = get_junos_commands();
  foreach cmd (local_commands_list)
  {
    kb = str_replace(string:cmd, find:" ", replace:"_");
    kb = str_replace(string:kb, find:"/", replace:"");
    kb = "Host/Juniper/JUNOS/Config/" + kb;
    raw_cmd = cmd;

    buf = get_kb_item("Secret/"+kb);
    if(!isnull(buf))
    {
      dbg::detailed_log(lvl:2, src:fn, msg:'Command [' + cmd + '] already found in KB.');
      continue;
    }
    if (no_more && "| no-more" >!< cmd)
      cmd += " | no-more";

    cmd = junos_format_cmd(cmd:cmd, flag:shell);
    dbg::detailed_log(lvl:1, src:fn, msg:'Running command: ' + cmd);
    output = session.run_exec_command(command:cmd);

    if(check_command_output_junos(data_buf:output))
    {
      # set kb item
      replace_kb_item(name:"Secret/"+kb, value:output);
      write_compliance_kb_junos(command:raw_cmd, result:output);
    }
    else
    {
      # command failed with error, so set KB item to communicate to junos plugins so they don't try to re-run it
      replace_kb_item(name:"Secret/"+kb, value:"nessus failed to run command");
      if(isnull(output)) write_compliance_kb_junos(command:raw_cmd, result:"no results found");
      else write_compliance_kb_junos(command:raw_cmd, result:output);
      if(isnull(output)) output = '';
      dbg::detailed_log(
        lvl:1,
        src:fn,
        msg:'Command [' + cmd + '] failed to run or produce an output.',
        msg_details:{"Output" : {"lvl": 2, "value": output}});
    }
    # sleep to prevent junos SSH rate limiting from kicking in
    sleep(sleep_value);
  }

  return TRUE;
}
