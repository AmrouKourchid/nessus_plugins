#TRUSTED 2329ed691ffe06b45ce699800356604fced12a38bcc610e06e1905b75b1b1a0ebcb8ca947d4aa34f4452ae542fa4c34b78fd5190448a6a5c643e96d6d914df54fb65690052daae4b43f7708cbe30c1afbf93d956026cd04e5644b59cdfb81000becf523c62bed924588fa7d3ce2def541ceee7e742b86ba47ce11bdbb0e0cc721c6fb25504c07d8d48690f02ab4bd4de14f1662c0553483dc5bf540b94c17880d1213511aeeab8bfdc265888e5eec4e4631ed42e405de3a642fc2d3a755225825f7cae870646570e4ad40744e90a76701d42377f478a244f6190c52e9d94a10c75e25601947eb4ac66d8130e00128bcca4605bf725122c13b78cafba69cff6a7846f43fb2e9aa6cc7e9b1a53e51e093219bfb5c343d8f5504be1250f83e7b8b727c35e3f12b32bee1949bc5ad25c09fa06157dfdc5c92eef454f4e2e7d22e14bcdb510c1ee842cacb958aa2a31ae404434f409509d29f607b6f2d70d6f5d1876809c6968e338aa44e4468dd867d9941b632b555e76c17d321372b2f0548e8bc647524dd19e77af4a4fbe1f92ecc4e5a347b0542229ba40312160a5d9e7539c1934344adf547fbbfc8f92707b19cd5b712681a16ead97bb0f71eb28b3b4d4b66aae3b25c4fc579ce41742ab3846a2fadd2247fd53d66fd5be413f877701ba0856235be0839817ecff182464f4b5b7d314d63de8e39eb41b695f9988a46f48a9bb
#TRUST-RSA-SHA256 3ff167bf7f790bdf1a56885eb8b51ba16e0134deed18b4ef3d2e7006fcb56a5959270cf796180f9896e75cc57e0cd748228c060b642e75b8bd62cd8e93bf058bbfe2bca36242f706e51eabcce962bfd5ac2e4c178e666de82157b995580070bbe60a23761eaeaab03c3395814fb0eefed2e14b0d365746bbac250ed861c879ca49c0f13d9065c9f875a0f1e1fbdb5772b166164bcdc738840d141838d27bfb6565aa85cf8b479a8153b3735ad41adcc2f15824185a889b5c85c7a482a420bf8c838ffdf4e35d0ea49f34e762ffc7a6920eb9eb3ad8737bc7582423df2302c2f3b0744e390b78115e1c10b47862f2dd960211e817fb02bd84eeedc6da0a89dcbe86a21057010532242c1d911ed87cf33a9bb81ab469340008ca7dc1eb5fcc4b8d340766118a2a451047641205fd66799b3b9febc557e2d03a8f46357408943c86639eee5bd058bbef6ea72cc5d8a1f12991bab12196e906356aceefca01e3af484dd5bd6db79218a796c489dd6fd4c3d582aaeec91bc9154580b8fc06c488645a172a15106d2468b99d13ff048767784f2556b5dc8f9a59bd67250e0862c070cb32b244080bf9fb467232dbbf74056c2c1d155a3f4e8391abcbf61c485c92fbdf5caa510a2100716911fdaa404304858ed8788343a1106931ea7d1321ece2de90eaf8a20b184f86374b8df6f98ed708df1d89a66f4e49d602c74f49fe7dc4b8e6
#
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.22
###

include("compat_shared.inc");
include("ssh_func.inc");
include("ssh_lib.inc");
include("hostlevel_funcs.inc");
include("lcx.inc");

enable_ssh_wrappers();

##
# Attempt to determine if the enable password is required
#
# @return 1 is yes, 0 if no
##
function cisco_needs_enable()
{
  local_var buf, prompt, priv_level;
  local_var is_ftd = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');

  # There's no enable or enable password for FTD, so always return 0
  if (is_ftd)
    return 0;

  buf = _FCT_ANON_ARGS[0];

  # if local checks are not enabled, then there is no need for enable
  if (!get_kb_item("Host/local_checks_enabled")) return 0;

  # if buf is empty/blank then assume enable is NOT needed
  if (!buf) return 0;

  # Check the command prompt to see if 'enable' was successful.
  prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
  if (
    !isnull(prompt) &&
    preg(pattern:"#[ \t]*$", string:prompt)
  ) return 0;

  # check if we are indeed privilege level 15
  # if so assume the error is indeed an error
  priv_level = get_kb_item('Host/Cisco/show_privilege');
  if(!isnull(priv_level) && priv_level == 15 && report_paranoia < 2)
    return 0;

  # check for various error messages used to identify when level 15
  # privs are needed
  # 
  # error message for IOS XR
  if ("% This command is not authorized" >< buf) return 1;
  # error message for IOS, ASA
  if ("ERROR: Command authorization failed" >< buf) return 1;
  # error message for IOS XE
  #if ((get_kb_item("Host/Cisco/IOS-XE") && ("" >< buf)) return 1;
  # error message for NX-OS
  #if ((get_kb_item("Host/Cisco/NX-OS") && ("" >< buf)) return 1;
  # error message for IPS
  #if ((get_kb_item("Host/Cisco/IPS") && ("" >< buf)) return 1;
  # error message for WLC
  #if ((get_kb_item("Host/Cisco/WLC") && ("" >< buf)) return 1;
  # error message for NAM
  #if ((get_kb_item("Host/Cisco/NAM") && ("" >< buf)) return 1;
  # error message for CNU-OS
  #if ((get_kb_item("Host/Cisco/CNU-OS") && ("" >< buf)) return 1;
  # error message for CUC
  #if ((get_kb_item("Host/Cisco/CUC") && ("" >< buf)) return 1;

  if ("% Invalid input detected at " >< buf ) return 1;

  return 0;
}

##
# Determines if the buf returned is an error or a valid result
#
# @return 1 is good, 0 if bad/error
##
function check_cisco_result()
{
  local_var buf;
  local_var is_ftd = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');
  buf = _FCT_ANON_ARGS[0];

  if (!buf) return 0;
  if (cisco_needs_enable(buf)) return 0;
  if ("% This command is not authorized" >< buf) return 0;
  if ("% Invalid input" >< buf) return 0;
  if ("ERROR: " >< buf) return 0;
  if (is_ftd)
  {
    # Bell indicates an error
    if ('\x07' >< buf) return 0;
    if ('Syntax error: Illegal parameter' >< buf) return 0;
  }

  return 1;
}

##
# Handles emulating derivatives of the 'show run' command.
#     Pulls show running-config/show running-config all output from the
#     stored KB item, handles scoping the command (show running-config $scope)
#     and output modifiers (show running-config | include $regex)
# WARNING: Passing untrusted input to this function may result in unexpected command execution
#
# @param cmd The command to emulate
# @param ftd Boolean that is true when we've authenticated to an FTD CLI
#
# @return emulated command results
#             output of command
#             empty string if there is no output
#             NULL if there was an error, or show run was not initially collected
##
function cisco_running_config_cmd(cmd, ftd)
{
  var running_config, running_config_all, matches, ret, config_category, include_str;

  var cmd_logger = new("sshlib::cmd_logger");

  if (ftd)
  {
    running_config = get_kb_item('Secret/Host/Cisco/FTD_CLI/1/show_running-config');
    running_config_all = get_kb_item('Secret/Host/Cisco/FTD_CLI/1/show_running-config_all');
  }
  else
  {
    running_config = get_kb_item('Secret/Host/Cisco/Config/show_running-config');
    running_config_all = get_kb_item('Secret/Host/Cisco/Config/show_running-config_all');
  }

  if(isnull(cmd) || (empty_or_null(running_config) && empty_or_null(running_config_all)))
    return NULL;

  var dbg_name = SCRIPT_NAME+'.'+FUNCTION_NAME+'.log';

  /*
     matches[0] = base show run/show running-config command
     matches[1] = all
     matches[2] = config context, after the base command but before | - this is treated
                    as a regex with ^ prepended. Checks for top-level context items, then
                    all following lines that are indented are included in the context
     matches[3] = any output modifiers after | - this is treated as a regex and passed
                    directry to preg
   */
  matches = pregmatch(pattern:"^ *show run(?:ning(?:[ -]config)?)? *(all)? *([^|]+)? *(?:\| *include +(.*))?$", string:cmd);
  if(isnull(matches))
  {
    return NULL;
  }
  else if(len(matches) == 1)
  {
    cmd_logger.add(cmd:cmd, response:running_config, emulated:TRUE);
    return running_config;
  }
  else if(!isnull(matches[0]) && !isnull(matches[1]) && isnull(matches[2]) && isnull(matches[3]))
  {
    cmd_logger.add(cmd:cmd, response:running_config_all, emulated:TRUE);
    return running_config_all;
  }


  if(matches[1])
    running_config = running_config_all;

  if(empty_or_null(running_config))
    return NULL;

  config_category = matches[2];
  include_str = matches[3];

  if(isnull(running_config))
    return NULL;

  if(!isnull(config_category))
  {
    var line, search, found;
    search = '^' + config_category;
    found = FALSE;
    ret = '';
    foreach line (split(running_config, sep:'\n', keep:TRUE))
    {
      if(!found && preg(pattern:search, string:line, icase:TRUE))
      {
        found = TRUE;
        ret += line;
        continue;
      }
      else if(found && leading_spaces(str:line) > 0)
      {
        ret += line;
        continue;
      }
      # Back at the top level, but this line may be for the same 
      # Setting. Reset found and check again.
      found = FALSE;
      if(preg(pattern:search, string:line, icase:TRUE))
      {
        found = TRUE;
        ret += line;
      }
    }
    if(!isnull(include_str))
    {
      ret = pgrep(pattern:include_str, string:ret, icase:TRUE);
    }
  }
  else if(!isnull(include_str))
    ret = pgrep(pattern:include_str, string:running_config, icase:TRUE);

  cmd_logger.add(cmd:cmd, response:ret, emulated:TRUE);

  return ret;
} 


##
# Returns the number of leading spaces in a string
#
# @param str string to test
#
# @return the number of leading spaces
##
function leading_spaces(str)
{
  var ret = 0;

  while(ret < strlen(str) && str[ret] == ' ') ret++;

  return ret;
}

##
# Checks to see if the requested kb_item exists.
#         If so, simply return the kb_item.
#         If not, then collect the data and set the kb_item.
#
# @anonparam kb_item The kb_item to check
#
# @anonparam cmd The cmd to gather the kb_item info
#
# @anonparam flag The flag to indicate whether or not to exit on unknown error
#                 1 = exit, 0 = continue as normal
#
# @return the value stored in the kb_item or gathered via
#         the cmd, or
#         NULL if there were any errors
##
function cisco_command_kb_item()
{
  local_var kb_item, cmd, ftd_cmd_kb_item;
  local_var buf;
  local_var flag;
  local_var is_ftd = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');
  local_var session, ch, sh;

  # get parameters
  cmd = _FCT_ANON_ARGS[1];
  # Firepower devices can have multiple FTD CLIs. The plugin writer should ensure that workarounds are only called if
  # we've authenticated directly to a singular FTD CLI, in which case kb items set by cisco_enumerate_firepower should
  # be stored as follows: under Host/Cisco/FTD_CLI/1/ and with spaces in the command. For commands run by
  # cisco_workarounds, we store these with Secret and spaces in the command. To avoid re-running commands, for FTD we
  # try to get a previously stored kb item both with and without Secret.
  if (is_ftd)
  {
    ftd_cmd_kb_item = ereg_replace(string:cmd, pattern:' ', replace:'_');
    kb_item = 'Secret/Host/Cisco/FTD_CLI/1/' + ftd_cmd_kb_item;
  }
  else
    kb_item = "Secret/"+_FCT_ANON_ARGS[0];
  flag = 0;
  if ( _FCT_ANON_ARGS[2] ) flag = _FCT_ANON_ARGS[2];

  # if no kb_item is specified, return
  if (!kb_item)
    return NULL;

  buf = cisco_running_config_cmd(cmd:cmd, ftd:is_ftd);
  if (!isnull(buf))
    return buf;

  # immediately return the command output if we already know it
  buf = get_kb_item(kb_item);
  if (buf)
    return buf;
  # cisco_enumerate_firepower also stores some commands without Secret, so check for these
  if (is_ftd)
  {
    buf = get_kb_item('Host/Cisco/FTD_CLI/1/' + ftd_cmd_kb_item);
    if (buf)
      return buf;
  }

  # if no command is specified, return
  if (!cmd)
    return NULL;

  # setup ssh tunnel and run command
  if (is_ftd)
  {
    session = new("sshlib::session");
    if(!sshlib::try_ssh_kb_settings_login(session:session))
      audit(AUDIT_FN_FAIL, 'sshlib::try_ssh_kb_settings_login');

    sh = new("sshlib::firepower_shell_manager");
    ch = session.open_shell(shell_handler:sh, skip_check_shell:TRUE);
    if (!ch) exit(1, "Failed to get channel");

    buf = sh.run_command(session:session, command:cmd, channel:ch, cmd_shell:sshlib::FP_SH_FTD);

    session.close_connection();
  }
  else
  {
    sock_g = ssh_open_connection();
    if (! sock_g) exit(1, "ssh_open_connection() failed.");

    # issue command
    buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
    ssh_close_connection();
  }

  if (buf)
  {
    # set kb item for future use
    set_kb_item(name:kb_item , value:buf );
  }
  if (buf && flag && !cisco_needs_enable(buf))
    exit(1, 'ERROR executing ['+cmd+'] = '+substr(buf,0,160));
  return buf;
}

##
# Examines sections of the Cisco running-config for the specified regular
# expression by using '!' as the default delimiter.
#
# @param string      config        'show running-config' or similar output 
# @param string      section_regex section(s) to look for via a PCRE   
# @param list|string config_regex  list of configs or single config to look for via PCREs
# @param string      delimiter     OPTIONAL end boundary for the section (default: '!')
#
# @return TRUE  if all config_regex(es) are found in the section(s) found by
#               using section_regex
#         FALSE otherwise
##
function cisco_check_sections(config, section_regex, config_regex, delimiter)
{
  local_var matches, match, found, config_regexes;
  local_var str, idx_end;

  if (empty_or_null(config))
  {
    err_print("cisco_check_sections: 'config' must be specified.");
    exit(1);
  }

  if (empty_or_null(section_regex))
  {
    err_print("cisco_check_sections: 'section_regex' must be specified.");
    exit(1);
  }

  if (empty_or_null(config_regex))
  {
    err_print("cisco_check_sections: 'config_regex' must be specified.");
    exit(1);
  }

  # Make a list always
  config_regexes = config_regex;
  if (typeof(config_regexes) != 'array')
    config_regexes = make_list(config_regexes);


  if (isnull(delimiter)) delimiter = "!";

  matches = egrep(pattern:section_regex, string:config);
  if (!empty_or_null(matches))
  {
    matches = split(matches, keep:FALSE);
    foreach match (matches)
    {
      found = 0;
      str = strstr(config, match);
      idx_end = stridx(str, delimiter);
      str = substr(str, 0, idx_end);

      foreach config_regex (config_regexes)
      {
        if (preg(string:str, pattern:config_regex, multiline:TRUE))
          found++;
      }

      if (found == len(config_regexes))
        return TRUE;
    }
  }
  return FALSE;
}
