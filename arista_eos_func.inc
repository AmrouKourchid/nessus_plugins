#TRUSTED 21d91dd9bc3cb31da12014d88ad9348c53b2668d3b843037e2f455ff1793295899bda8dcee3d4ba610dbea5b0337d3d18db5a199c2753e7a14f1be914b169f0feec4f31c7e8ba04e0fdc5739f4fca0efdcdef8a61899f43fc2f07bb96e335f51ddf131ef7bc88008358198afbd462006edaf403e75cbcf449b77a083dad0d57c5eb5dff2cedb11a20fb02a1bbc0ff1c7e14f9c8b3d0a3f0b716d63895b509da931f65d1c70c0861245d4bdce66a511bf05e7c86b0cc95f5c4300efd12144b7051c5c1957e02ad6b18bddd96292b3bce3ddb8af8103b61ac32262541270fbacdece2cdfa59f31024b228393b5472798f7d5e5ad21ffcf85f28d22ba5feba1bce20b88a0f99f699b459298d337cbddd86aab144bb376d1eb7fe0de2a62280af9fba8fd9d655f8f771d7a61c2b0d86234780bc1c05548dcf2d76e2db78442a5687053a8c38cf1cedb6a001728efe6ee817cdf79db6cd44a6cdf786d90d20f3f58d4d3c39da365bb4102c5bad315d18722725611c697ce3c0f5b519e27b8f3c3812e24bdf7e3df8e7f0ece08adb8535f5ae7dde35f138790019f21ecc4141a3cc0f76487b724ba0a340a472f86536654f7aa0193edb62b2e8c61a1c13fbc811e083ec9c6528810f3bcc6d1d0b9c22b65a3a5800204e0d9355125d5789fdf5ae65b3d6dd51541586699b3f93b049ae64ad332a9b68d9945256d44d37b6dfa224b1a05
#TRUST-RSA-SHA256 0989c6ebd1f696dbec233c5cf217ae4564be85a26e0a483a32988472939cfaa1d0dc408e494f9ddc349e666e801371a8fabe2ac1d1fc49f532e65ea5a4aa569e88f4bec02c83d856362f1e91766d6139bb7aa095a4798dc8427829a8c528e74982385be734b61e6d5cd58ff4c23eb0debdf90ba41e679ab65bac1854749b7e8c2ba4d79292fdc6d5e03d0a93e33cb9bde63c6c09d290e2e40cbd7efdd7b9f213c5abcce86f6e5d193d52e6981e6dbca652e0ab2c2f501b0e61802cb664364836656f89a6f371e59a7228e2e107b33c142769e4f2c886c7d15d56a2fe735216d7573a7c2ebdf8df5a38654ada29fa1088d1d7d954b5990819eae46ed81a828bc9a6cd559197b305c35f0e42d00ddca45b9cc314934e89da6613fb8a9952f0844bab7f418ff6da8e34dda820f33a4ea342ce47845bb052544a20ee2f98c564cfa98d44877e6d1dcdc6828dfe0788b58524c40f3ecf595ebf504cae93f80ad013a16f3c5c63a694475a5b65d678a143c80a048b1cbd15947ea973f0897d5831fe77b27c940674a24b8038e1bffe3d018b779156a84908971f0536d4425e2317166a561a2c4f82c927a76d78ac8cafadafc1ca37f6c12ca9f986207758797dd43f6c54cfd2f04c8382377437cc2befbf86140104a7bb20d3e92ded0f21c5568096aebce5b7bf11ef67ddff7b0eca00d02c75364f707c02f769a885372a63cb285356
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# arista_eos_func.inc
#
# Revision: 1.8
##

include("compat_shared.inc");
include("ssh_func.inc");
include("debug.inc");


global_var __REPORT_EXT_BOOT, __REPORT_NO_EXT;
global_var INSTALLED_EXT, BOOT_EXT;
global_var EOS_VERSION, EOS_FIX;
global_var EOS_DEFAULT_FIX = "See related advisory or contact Arista for support.";

##
# Determine if the version of EOS software on a remote system is
# inclusively between a given version range 
#
# @param vspec   string containing version/hotfix range information
#
# @return FALSE if version less than low range OR
#                  version greater than high range
#         TRUE otherwise
##
function _eos_inclusively_between(vspec)
{
  local_var lo,hi,ver;
  ver = EOS_VERSION;
  vspec = split(vspec,sep:"<=",keep:FALSE);
  lo = vspec[0];
  hi = vspec[1];
  ver = pregmatch(pattern:"^(\d+(?:\.\d+)+).*$", string:ver);
  ver = ver[1];
  if ( ver_compare(ver:ver, fix:lo, strict:FALSE) >= 0 && ver_compare(ver:ver, fix:hi, strict:FALSE) <= 0 )
    return TRUE;
  else 
    return FALSE;
}


##
# Check hotfixes if we were given creds which ssh into a bash shell.
#
# @return array containing:
#         "inst": an array of the installed extensions in the format
#               {<SHA512sum of extension> : <Extension filename>,...},
#         "boot" : < string of \n separated extension names which are enabled on boot>
##
function _shell_extension_check()
{
  local_var boot_buf, ext_buf, line, inst_array;

  ext_buf = get_kb_item("Host/Arista-EOS/sha512sum /mnt/flash/.extensions/*");
  if(empty_or_null(ext_buf))
  {
    ext_buf = eos_cmd(cmd:"sha512sum /mnt/flash/.extensions/*");
    ext_buf = ext_buf["value"];
  }
  boot_buf = get_kb_item("Host/Arista-EOS/cat /mnt/flash/boot-extensions");

  if(empty_or_null(boot_buf))
  {
    boot_buf = eos_cmd(cmd:"cat /mnt/flash/boot-extensions");
    boot_buf = boot_buf["value"];
  }

  inst_array = make_array();

  foreach line (split(ext_buf, keep:FALSE))
  {
    line = pregmatch(pattern:"^([0-9a-zA-Z]{128})\s+/mnt/flash/\.extensions/(.*\.swix)", string:line);
    if(empty_or_null(line)) continue;
    inst_array[line[1]] = line[2];
  }

  return make_array("inst", inst_array, "boot", boot_buf);
}
##
# Determine if the listed extensions/patches are installed
# on the EOS system.
#
# @param ext  the hotfix release string
#
# @param sha  for when we need to check the sha512 of the .swix (root/bash shell)
#
# @return FALSE if hotfix not installed or is installed but not on boot
#         TRUE if installed and runs on boot.
##
function eos_extension_installed(ext, sha)
{
  local_var cmd, installed_buf, boot_buf, swix, installed_array;
  local_var name, rpms, field, eoscli, extension;

  installed_array = make_array();
  eoscli = get_kb_item("Host/Arista-EOS/eos_shell");

  if(empty_or_null(eoscli))
  {
    extension = sha;

    if(empty_or_null(INSTALLED_EXT))
    {
      installed_array = _shell_extension_check();
      boot_buf = installed_array["boot"];
      installed_array = installed_array["inst"];
    }
    else
    {
      installed_array = INSTALLED_EXT;
      boot_buf = BOOT_EXT;
    }

    if(empty_or_null(installed_array))
    {
        __REPORT_NO_EXT = TRUE;
        return FALSE;
    }
    else
    {
      INSTALLED_EXT = installed_array;
      BOOT_EXT = boot_buf;
    }
  }
  else
  {
    extension = ext;
      # Avoid sending ssh cmds again.
    if(empty_or_null(INSTALLED_EXT))
    {
      installed_buf = get_kb_item("Host/Arista-EOS/show extensions detail");
      if(empty_or_null(installed_buf)) 
      {
        cmd = "show extensions detail";
        installed_buf = eos_cmd(cmd:cmd);
        installed_buf = installed_buf["value"];
      }

      if(empty_or_null(installed_buf))
      {
        __REPORT_NO_EXT = TRUE;
        return FALSE;
      }

      foreach swix (split(installed_buf, sep:"Name: ", keep:FALSE))
      {
        name = split(swix,keep:FALSE);
        name = chomp(name[0]);
        rpms = pregmatch(pattern:"RPMS: (.*)\n", string:swix);
        if(!empty_or_null(rpms) && !empty_or_null(rpms[1]) && "Status: installed" >< swix && ext >< rpms[1])
        {
          installed_array[ext] = name;    
        }
      }
      INSTALLED_EXT = installed_array;
    }
    else installed_array = INSTALLED_EXT;

    # If none of the desired hotfixes were installed
    if(empty_or_null(installed_array)) return FALSE;

    # Avoid sending ssh cmds again.
    if(empty_or_null(BOOT_EXT))
    {
      boot_buf = get_kb_item("Host/Arista-EOS/show boot-extensions");
      if(empty_or_null(boot_buf))
      {
        cmd = "show boot-extensions";
        boot_buf = eos_cmd(cmd:cmd);
        boot_buf = boot_buf["value"];
      }
      BOOT_EXT = boot_buf;

    }
    else boot_buf = BOOT_EXT;
  }

  # Still report vuln if the hotfix isn't in boot-extensions
  if(!empty_or_null(installed_array[extension]) && installed_array[extension] >< boot_buf)
  {
    __REPORT_EXT_BOOT = FALSE;
    return TRUE;
  }
  else if (installed_array[extension] >!< boot_buf && !empty_or_null(installed_array[extension]))
  {
    __REPORT_EXT_BOOT = TRUE;
    return FALSE;
  }
  else return FALSE;
}

##
# Determine if the system has Cloud Vision Exchange server enabled
#
# @param exit_on_error  bool that exits if nessus cannot check
#                       whether CVX is enabled
#
# @return TRUE if cvx is enabled
#         FALSE otherwise
##
function get_cvx(exit_on_error)
{
  local_var cvx, value;
  if(empty_or_null(exit_on_error)) exit_on_error = TRUE;

  cvx = get_kb_item("Host/Arista-EOS/cvx");
  if(empty_or_null(cvx)) 
  {
    cvx = eos_cmd(cmd:"show cvx");
    cvx = cvx["value"];
  }
  if(!empty_or_null(cvx))
  {
    if(cvx =~ "Status:\s+Enabled")
      return TRUE;
    else if (cvx =~ "Status:\s+Disabled")
      return FALSE;
    else 
    {
      if(exit_on_error)
        exit(0, "Could not determine if Cloud Vision Exchange was enabled.");
    }
  }
  if(exit_on_error)
    exit(0, "Could not determine if Cloud Vision Exchange was enabled.");
  return FALSE;
}

##
# Determine if the system has SNMP Service enabled
#
#
# @return TRUE if SNMP Service enabled
#         FALSE otherwise
##
function eos_snmp_service()
{
  var eos_snmp;

  var ext_snmp = get_kb_item('Host/Arista-EOS/show snmp enabled');
  if (empty_or_null(ext_snmp))
  {
    eos_snmp = eos_cmd(cmd:"show snmp");
    eos_snmp = tolower(eos_snmp["value"]);

    if (!empty_or_null(eos_snmp))
    {
      if (eos_snmp =~ "snmp agent enabled")
        replace_kb_item(name:'Host/Arista-EOS/show snmp enabled', value:'1');
      else
        replace_kb_item(name:'Host/Arista-EOS/show snmp enabled', value:'0');
    }
    else
      replace_kb_item(name:'Host/Arista-EOS/show snmp enabled', value:'0');
  }
}

##
# Run a cmd on the EOS shell (e.g. show ver/show installed-extensions, etc)
# Also output the result to kb if successful (Host/Arista-EOS/<cmd>=value)
#
# @param cmd    The command to run
#
# @return array:
#               Error: Contains relevant message if there is an issue, NULL otherwise.
#               Value: NULL if there is an error, cmd output otherwise.
# 
##
function eos_cmd(cmd)
{
  local_var sock_g, value, error;
  value = NULL;

  sock_g = ssh_open_connection();
  if (! sock_g){
    return make_array("error", "Could not connect", "value", NULL);
  }

  value = ssh_cmd(cmd:cmd, nosh:TRUE);

  ssh_close_connection();

  if(empty_or_null(value))
    return make_array("error", "No output received", "value", NULL);
  else if ("% Invalid input" >< value)
    return make_array("error", "Invalid command", "value", NULL);

  replace_kb_item(name:"Host/Arista-EOS/"+cmd, value:value);
  return make_array("error", NULL, "value", value);

}

##
# Determine if a remote EOS host is affected via a vulnerability matrix (vmatrix)
# of affected and unaffected versions.
# @param  vmatrix an object with a structure similar to:
# vmatrix["all"] =  make_list("4.10.1<=4.12.99");
# vmatrix["F"] =    make_list("4.13.1.1<=4.13.6",
#                             "4.14.0<=4.14.4.2", 
#                             "4.15.0<=4.15.6"
#                             );
# vmatrix["M"] =    make_list("4.13.7<=4.13.15",
#                             "4.14.5<=4.14.15",
#                             "4.15.5<=4.15.6"
#                             );
# vmatrix["misc"] = make_list("4.14.5FX",
#                             "4.14.5FX.1",
#                             "4.14.5FX.2", ...
#
#
# @return FALSE if the EOS host is not affected
#         TRUE otherwise
##
function eos_is_affected(version, vmatrix)
{
  local_var f,m,rel,fix,ext_installed,vuln,pat,hf, f_re, m_re, rel_re;
  local_var affected_f, affected_m, affected_misc, affected_all;
  vuln = FALSE;

  EOS_VERSION = version;

  affected_f    = vmatrix["F"];
  affected_m    = vmatrix["M"];
  affected_misc = vmatrix["misc"];
  affected_all  = vmatrix["all"];
  fix           = vmatrix["fix"];

  if(empty_or_null(fix)) fix = EOS_DEFAULT_FIX;

  # Check the feature versions
  if(version =~ "^\d+(\.\d+)+F$" && !empty_or_null(affected_f))
  {
    foreach f (affected_f)
    {
      f_re = ereg_replace(string:f, pattern:"\.", replace:"\.");
      if("<=" >< f) vuln = _eos_inclusively_between(vspec:f);
      else if(version =~ "^"+f_re+"([^0-9]|$)") vuln = TRUE;
      if(vuln) break;
    }
  }
  # Check the maintenance versions
  else if(version =~ "^\d+(\.\d+)+M$" && !empty_or_null(affected_m))
  {
    foreach m (affected_m)
    {
      m_re = ereg_replace(string:m, pattern:"\.", replace:"\.");
      if("<=" >< m) vuln = _eos_inclusively_between(vspec:m);
      else if(version =~ "^"+m_re+"([^0-9]|$)") vuln = TRUE;
      if(vuln) break;
    }
  }
  # Check versions with unique suffixes
  else if(!empty_or_null(affected_misc))
  {
    foreach rel (affected_misc)
    {
      if ( version == rel ) vuln = TRUE;
      if(vuln) break;
    }
  }
  # if not yet vuln, check the "All releases in" affected versions.
  if(!empty_or_null(affected_all) && !vuln)
  {
    foreach rel (affected_all)
    {
      rel_re = ereg_replace(string:rel, pattern:"\.", replace:"\.");
      if("<=" >< rel) vuln = _eos_inclusively_between(vspec:rel);
      else if(version =~ "^"+rel_re+"([^0-9]|$)") vuln = TRUE;
      if(vuln) break;
    }
  }

  if(vuln) EOS_FIX = fix;

  return vuln;
}

##
# Generates a report about the Arista EOS device/software
# Including the installed version, the fixed version
# and details regarding a hotfix/patch or mitigation.
#
# @return A string with the report information gathered during 
#         the last call to eos_is_affected(....).
##
function eos_report_get() 
{
  local_var report;
  report += '\n  Installed Version : ' + EOS_VERSION +
            '\n  Fixed Version     : ' + EOS_FIX;

  if(__REPORT_NO_EXT)
    report += '\n  Either no hotfixes were present or Nessus was not able to check for hotfixes using the credentials provided.';
  if(__REPORT_EXT_BOOT)
    report += '\n  The appropriate hotfix has been installed, but it will not be loaded at system boot. The hotfix should be added to boot-extensions.';
  report += '\n';

  return report;
}

namespace arista_host_ip_enum
{
  var HOSTNAME_KB_KEY = 'Host/Arista/EOS/show_hostname';
  var NW_INTERFACE_KB_KEY = 'Host/Arista/EOS/show_interfaces';

  ##
  # Extracts device's hostname from the output of `show hostname` command.
  #
  # @param [show_hostname_cmd_output:string] Optional output of the said command - if not provided, defaults to "Host/Arista/EOS/show_hostname" KB entry
  #
  # @return Hostname string, if found, NULL otherwise.
  ##
  function get_hostname(show_hostname_cmd_output)
  {
    if(empty_or_null(show_hostname_cmd_output)) show_hostname_cmd_output = get_kb_item(HOSTNAME_KB_KEY);
    if(empty_or_null(show_hostname_cmd_output))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing 'show_hostname_cmd_output'.");
      return NULL;
    }
  
    var hostname = pregmatch(string:show_hostname_cmd_output, pattern: "Hostname: ([^\s]+)");
    if(empty_or_null(hostname))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME,msg: "Hostname not found.");
      return NULL;
    }
    hostname = strip(hostname[1]);
    return hostname;
  }

  ##
  # Extracts all device's IPv4 addresses from the output of commands specified at the top of this file.
  # IPv4 addresses will be parsed from ``NW_INTERFACE_KB_KEY``.
  #
  # @param [system_interface:string] Optional output of the said command - if not provided, defaults to NW_INTERFACE_KB_KEY KB 
  # @param [ip_ver:string] Set the IP version to retrieve to 'IPv4' or 'IPv6' - defaults to IPv4
  #
  # @return An array of {interface name:[IPv4/IPv6 address strings]}, if found, NULL otherwise
  #
  ##
  function get_ip_array(system_interface, ip_ver)
  {
    if (empty_or_null(system_interface))
    {
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: 'Retriving network interface information from saved kb item.',
        msg_details: {
          "NW_INTERFACE_KB_KEY": {"lvl": 2, "value": NW_INTERFACE_KB_KEY}});
      system_interface = get_kb_item(NW_INTERFACE_KB_KEY);
    }

    if (!ip_ver || tolower(ip_ver) == 'ipv4') ip_ver = 'IPv4';
    else if (tolower(ip_ver) == 'ipv6') ip_ver = 'IPv6';
    else return NULL;

    if (!empty_or_null(system_interface))
    {
      var any_address_found = false;
      var match;
      var config_lines = split(system_interface, keep:FALSE);
      var addresses = {};
      var interface_regex = "^(.*?) is (?:down|up)";
      var last_interface = NULL;
      var ip_regex;
      if (ip_ver == 'IPv4') ip_regex = "Internet address is (\d+(?:\.\d+){3})";
      else ip_regex = "address is ([0-9a-fA-F:.]+)";

      foreach (var line in config_lines)
      {
        match = pregmatch(string:line, pattern:interface_regex);
        if(!isnull(match))
        {
          last_interface = match[1];
          addresses[last_interface] = [];
          continue;
        }

        if ('Broadcast' >< line) continue;
        match = pregmatch(string:line, pattern:ip_regex);
        if(!isnull(match) && last_interface)
        {
          append_element(var:addresses[last_interface], value:match[1]);
          any_address_found = true;
        }
      }
    }
    if (empty_or_null(addresses) || !any_address_found) return NULL;
    return addresses;
  }
}
