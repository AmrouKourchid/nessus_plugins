#TRUSTED 3dab3ed6e4024eb5a97a56259155cb05391a6bf05235cfa33a445d1d2beda79717b61ec60f5c63773271b07af5368d0e705cda907eb085c3b870aa71e27c65a4236d19add4f4781b6694b921d1f53305c24af162aa6d4dd43594313ea7f34436125819c44d2c75946ee619df0b5f35ba3e7a80a7e9ea7cda7d4f88f56f058b87bb384250dadb4be14a0617819cc9135fa50ed07cbddc7ca91e14afef2be8a183b8958b1cc98b466adbae04806f82854e54f3bc8c47be480ccc5234879e3756252671c2a5ca8788ef8107005b515fa4d12528ccc5d8e95702e3656e2d29d504582824ddc368a49082cd88d5dbaed99e07a4b3f6b3ab0dd0000d5bbdd2e38a46768f3938142fad4326e91a71fc7a3531cedcf90eb45568091c85746cf254891edb2626223dd4f599dba3b711b6418595e75d0714a919f32e87d5a71517707088870e772f2552f2fd2881db0e1cf8a23acf7172df68411560f173be10ff1e939cda9320f5cb9cf26685766f8077a9333e5520ef7bb0121725314e9fb13772803e28371ae0cc02f2dde8ef5381a731a09ac36504afd9dc892f6d567d86294e8a6816f860d78c87a38556e9c4048cc34491f29bdfc677a28b2362c19455a95c0eacc4fd93e583614712bbc8ead344d0059f49ff6a265b5ffebded122c205fa586cd9ca451acf06f17203dc2e03e1b12e071422e133c6e2d5678b59856676e63eecbeb
#TRUST-RSA-SHA256 54a96efde9366d1a06c5e6990d42983870e6b28ebbba1cdc12eb60db334bee2f6fd6a163a82b6bd53fd06141c89faca095d60ea7a83da6b7e9f9f535e121f0a15e15a569d1bc51303e6ba91c4b96f5f6ce4914ee3e027d1da9017092c4b12cc3b57d08c39ab91262f39ed4647750040edb1989016be61f737b11b9008ffbdbdb9d7ab2d395f632d5dd98f45f53ae18c9f95e807eef6a86ce67f7890c34a8dafdfb22b56eeb24702d241ffbdf643134911018d5ae041b7d5a218d2d5263523520c90a60904a5433c6becb2038be0fe97066571140ec675d25465bd742bc9c32343e2c45679e24815ed2806275aa855f3aa8d3b3a8c874240f9f7803864995456f4b00c4c6906980289b222ac8825b3b24dc1d44f1931aba22a2162b87dd400e704153cefa508b7f0fe23a804d6e16df218870fa63649968c7dfcdc0478348f913e081186834525c3a9f277aaf0b79c87257e2e4ee7d161dfc1f3a6bc158cb1d94d0219b57e11c7b3d78e4c5f44f37fe1773d9cb3c4498df159e686b05dedc7016099a9c577cfc292303dc4d89eef6e528ed88f34e22da3ade5c8fcdca577c46d313bafe295c8bd5c0c95b764dae3b3cbb4d1b967513eb49c1f599487cac1314fdf949fd1687cdf3b6e3413fcfe97afc38a75bd41f2c896f8f4067f0809bc932e38f5c31a53562d65aca400eab2d2d2122fb2a84ba35f8b788d15d2a2ed923ce26
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.8
###

include("compat_shared.inc");
include("junos.inc");
include("ssh_globals.inc");
include("ssh_func.inc");
include("ssh_lib.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

enable_ssh_wrappers();

##
# Determines if the output returned is an error or a valid result
#
# @return TRUE  if the output appears valid
#         FALSE if the output appears to be an error or invalid
##
function junos_check_result()
{
  local_var buf;
  buf = _FCT_ANON_ARGS[0];

  if (isnull(buf)) return FALSE;
  if ("syntax error, expecting <command>" >< buf) return FALSE;
  if ("unknown command" >< buf) return FALSE;

  return TRUE;
}

##
# Checks if the statement is deactivated or disabled
#
# @param string  buf       return buffer from Junos command
# @param string  pattern   to check for configuration
# @param boolean multiline OPTIONAL pass to preg (default: TRUE) 
#
# @return TRUE  if the configuration is enabled
#         FALSE if the configuration is not found or disabled
##
function junos_check_config(buf, pattern, multiline)
{
  local_var statements, lines, line;
  local_var deactivate_pat, disable_pat, matches;

  if (isnull(pattern))
  {
    err_print("junos_check_config: 'pattern' must be specified");
    exit(1);
  }

  if (isnull(multiline)) multiline = TRUE;

  statements = pgrep(string:buf, pattern:pattern);
  if (statements == '')
    return FALSE;

  lines = split(statements, sep:'\n', keep:FALSE);
  foreach line (lines)
  {
    # Look for deactivated statement in the config
    deactivate_pat = str_replace(string:line, find:"set", replace:"deactivate", count:1);
    if (preg(string:buf, pattern:deactivate_pat, multiline:TRUE)) continue;

    # Look for disable statement in the matching statements
    if (line =~ " disable$") continue;

    disable_pat = "^" + line +  " disable$";
    if (preg(string:statements, pattern:disable_pat, multiline:TRUE)) continue;

    return TRUE; # Statement was found not deactivated or disabled
  }

  return FALSE;
}

##
# Checks if the specified KB item exists.
#   If it does, simply return the output stored in the KB item.
#   If it doesn't, execute the specified command and store the output in the KB item.
# WARNING: Passing untrusted input to this function may result in unexpected command execution
#
# @param string  cmd the command to gather the KB item info
#
# @param string  kb      OPTIONAL KB item to check
# @param boolean no_more OPTIONAL do not paginate command output (default: TRUE)
#
# @remark 'kb' should only be specified for commands with special characters or
#         where the KB deviates from the command in some way
#
# @return output from executed command
#         FALSE  if local checks is not enabled
#         NULL   if there were any errors
##
function junos_command_kb_item(cmd, kb, no_more)
{
  local_var shell, buf;

  if (!get_kb_item("Host/local_checks_enabled")) return FALSE;

  if (isnull(cmd))
  {
    err_print("junos_command_kb_item: 'cmd' must be specified");
    exit(1);
  }

  shell = get_kb_item("Host/Juniper/JUNOS/shell");

  if (isnull(no_more)) no_more = TRUE;

  # Replace whitespaces with underscores and remove forward slashes for KB
  if (isnull(kb))
  {
    kb = str_replace(string:cmd, find:" ", replace:"_");
    kb = str_replace(string:kb, find:"/", replace:"");
    kb = "Host/Juniper/JUNOS/Config/" + kb;
  }
  # Add the 'no-more' display filter to not use pagination (enabled by default) 
  if (no_more && "| no-more" >!< cmd)
    cmd += " | no-more";

  # Return the command output if we already know it
  buf = get_kb_item("Secret/"+kb);
  if("nessus failed to run command" >< buf) return NULL;
  if (!isnull(buf)) return buf;

  # Issue specified command
  if (shell)
  {
    if (islocalhost())
    {
      if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
      info_t = INFO_LOCAL;
    }
    else
    {
      info_t = INFO_SSH;
      if (!ssh_open_connection()) exit(1, "Failed to open an SSH connection.");
    }

    if ("|" >< cmd) cmd = str_replace(string:cmd, find:"|", replace:"\|");
    buf = info_send_cmd(cmd:'cli ' + cmd);
    if (info_t == INFO_SSH) ssh_close_connection();
  }
  else
  {
    if (!ssh_open_connection()) exit(1, "Failed to open an SSH connection.");
    buf = ssh_cmd(cmd:cmd + '\r\n', nosudo:TRUE, nosh:TRUE);
    ssh_close_connection();
  }

  if (junos_check_result(buf))
  {
    set_kb_item(name:"Secret/"+kb, value:buf); # set KB item for future use
    return buf;
  }
  else return NULL;
}

##
# Returns a message that the configuration was not checked
#
# @anonparam TRUE  if configuration was not checked
#            FALSE if configuration was checked
# @param     boolean display generic caveat message (no reason in message)
# @return NULL if local checks are enabled and FALSE is passed
#         caveat string if local checks are not enabled or TRUE is passed
##
function junos_caveat(generic)
{
  # Configuration was checked
  if (get_kb_item("Host/local_checks_enabled") && !_FCT_ANON_ARGS[0]) return NULL;

  # Generic message
  if (!isnull(generic) && generic)
    return
      '\nNote that Nessus has not tested for this issue or the host ' +
      '\nconfiguration instead it has instead relied only on the ' +
      '\napplication\'s self-reported version number.\n';

  # Configuration was not checked because...
  #  local checks are not enabled
  if (!get_kb_item("Host/local_checks_enabled"))
    return
      '\nNote that Nessus has not tested for this issue or the host ' +
      '\nconfiguration because local checks are not enabled. Instead, ' +
      '\nNessus has relied only on the application\'s self-reported ' +
      '\nversion number.\n';
  #  an error occurred
  else
    return
      '\nNote that Nessus has not tested for this issue or the host ' +
      '\nconfiguration because an error occurred while attempting to test. ' +
      '\nInstead, Nessus has relied only on the application\'s self-reported ' +
      '\nversion number.\n';
}

##
# Reports and, if relevant, sets PCI KB(s) and include caveat message in report
#
# @param ver      string  installed version
# @param fix      string  fixed version
# @param override boolean display caveat message
# @param severity integer report severity SECURITY_(NOTE, WARNING, HOLE)
# @param model    string  OPTIONAL detected model
# @param xss      boolean OPTIONAL set XSS KB item
# @param xsrf     boolean OPTIONAL set XSRF KB item
# @param sqli     boolean OPTIONAL set SQLi KB item
#
# @return This function has no return values
##
function junos_report(ver, fix, override, severity, model, xss, xsrf, sqli)
{
  local_var port, extra;

  port = 0;  
  extra = NULL;

  if (xss)  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (xsrf) set_kb_item(name:'www/0/XSRF', value:TRUE);
  if (sqli) set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
    extra = get_report(ver:ver, fix:fix, model:model) + junos_caveat(override);
  else
    extra = junos_caveat(override);

  security_report_v4(port:port, extra:extra, severity:severity);
}
