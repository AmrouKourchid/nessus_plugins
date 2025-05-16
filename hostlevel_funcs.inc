#TRUSTED a5e25f40370c78729c07628114fa19c4a85b3ea020ac9b2652cc5fe16cf254510b7b04873c420427960d9d0bc3ec4c97d82760c3bf3f16fd2631d6701b83b46b23f735769bc495517e51d922779de5cf7cf386f5e33081ecfad107ca2eb623e68d75b0eac1e2bf41d81a4b4a369f6ff7f0683d8a071fd29502f85e29fc73a0ecb9fd239031f9efe1e5a1d2d5232832b40cc1f0245514156eb3fb3c5814376c7068ab7c3da83eb64abc9dfc9fc10bcc9ba131f3b4056d0d4c14415a9a0914832243840014a7aa9a40c013460bded5f6c5d62ffb4b8877b02e5ce06990108ab922eb249d775a7e21f982c9d69b664c32a87f739024c6b6b97faea3e4c71e329d46e45d0b3491df5b22e85358734bfe2e1e209e269d04ca04cd61251754d5e9020b72f3f6c1ecc8bb082ea21b36b601522e2ecafd8c45f8a35f21724e7ff0a124156b46ed59e5d26f4901002d64539ccfe1b57942fe6e10502922b8a949099e390c908861c85477fbcbd1a52b8cc5496a83f762eac60a9703af30855b97837c76cec16b0bc947b21f7bec07c4214d41c64ee31eb86a1dd4762c967b55bf08fb22e1acabb29de09a5eadf5d5657096ac3f863c0bef9aded70bbfd10f48d577d3505942659bc8886dad3840f179ec863d3d735426e381c3ad21d608c55e983fb4d5ed1526a081e9814544f68e201efee9891bc579661191416366cf4f82cfc9bb1e6e
#TRUST-RSA-SHA256 a65042e18ffd612654e976bfdc617d45745f1162cf61767c08486d3327d66be0ba341abe80bb03cb2c892ad485319821c529c58e5053c28afdf20bbf1c143127342859c40ef96aa86defef1508400065be93248137674fcad20cd2dffc2d9a5d6c3d7a56a3f626e52114eae4662d000444136c574eee95a53ac12e06e469d957a013f66d303c56d50ea643488dd4f75b4aad2162c5b87445109508bb27eff4b6d92947869e4c41e8346d40c53a793c8fe9511d8652fca6168a2618a807ff1c1a7738fcbe6c35a2088d9ae28bc5a21f1e31ac35ddf5e7c8a4496fb08641613f913bbc91669be3aea99a19f07ff784f69f1f8f8eb1f69bbd6f33f403d0bee439e8db4b1fa9bc2e8144e9f24cdf959e57058db493ec6ec31d124701f3d8395ad7a223cfe8eec49874778af58e1214d3da06e97fd958d851f1a43b2410eb936b1a76bc3a5990ef8f933643f71e28b15b04cbf38e47176131e967e8a4baa493b64b6cb9c3b0cf22ac21e644c2e9ffed72d691289affcd4fc15efc1802725ed60d054cb324a080fe14498411625d840dc45f94d65c81afe1bd17567f1c913303b653fb284d04b8bf88181885fbe07bc13b1380587c38ef8daa5bfb7b38cee72376c15faa4f4a2b445d7c21cd63df879b2e6dc394ae7072fddd8da045231a6e841b213c4832d5426c29bf6fb6f3baddb58bdc184a0597ccd0a3671bcad2712a01ff52fc
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# hostlevel_funcs.inc
#
# Revision: 1.31
#

include("compat_shared.inc");
include("nessusd_product_info.inc");
include("spad_log_func.inc");
include("telnet_func.inc");
include("ssh_func.inc");
include("ssh_globals.inc");
include("debug.inc");
include("lcx.inc");

#pragma static(include)
include("hostlevel_funcs.static");
#pragma static(include:false)

##
# Run ssh/telnet/rsh/rexec/local command
#
# @param cmd Command to run
# @param timeout A caller provided timeout (currently SSH only)
# @param nosudo Disables sudo in ssh_cmd
# @param force_priv_escl Passes through to ssh_cmd() to be passed to
#                        sshlib if wrapper functions are enabled
# @param pread_options Options to pass to pread_ex() for agents
#
# @return NULL if error or result of command as string
##

function info_send_cmd_impl(cmd, timeout, nosudo, force_priv_escl, pread_options)
{
  local_var buf, f, env_vars, unit_test;

  unit_test = get_one_kb_item("Unit_Tests/hostlevel_funcs/info_send_cmd_null_response");
  if (!empty_or_null(unit_test))
    return NULL;

  unit_test = get_one_kb_item("Unit_Tests/hostlevel_funcs/info_send_cmd_response");
  if (!empty_or_null(unit_test))
    return unit_test;

  env_vars = nasl_environment();

  if (info_t == INFO_LOCAL)
  {
    cmd = tenable_utils_replacement(cmd);

    # exclude cat cmds that direct or pipe stdout
    if (match(string: cmd, pattern: "cat *") && (">" >!< cmd && "|" >!< cmd))
    {
      # remove cat and a space to leave just the path, then remove any single quotes
      f = substr(cmd, 4);
      f = str_replace(string:f, find:"'", replace:"");
      if (! file_stat(f))
      {
        buf = 'info_send_cmd: "' +  f + '" does not exist or cannot be read\n';
        #debug_print(buf);
        local_log_command_and_response(command: "NASL command file_stat (" + f + ")", response: buf);
        return NULL;
      }
      else
      {
        buf = fread(f);
        local_log_command_and_response(command: cmd, response: buf);
        return buf;
      }
    }
    else if (cmd =~ "^cmd /C")
    {
      var arg_list = split(cmd, sep:' ', keep:FALSE);
      buf = pread_wrapper(cmd: arg_list[0], argv: arg_list, options: pread_options);
      local_log_command_and_response(command: cmd, response: buf);
      return buf;
    }
    else if (!isnull(env_vars) && !isnull(env_vars['os']) && env_vars['os'] == "WINDOWS")
    {
      buf = 'info_send_cmd: "' +  cmd + '" cannot be executed on this Windows localhost system.\n';
      local_log_command_and_response(command: "Shell command not run (" + cmd + ")", response: buf);
      return NULL;
    }
    else
    {
      if ("'" >< cmd) sep = '"';
      else sep = "'";
      buf = pread_wrapper(cmd: "/bin/sh", argv: make_list("sh", "-c", cmd), options: pread_options);
      local_log_command_and_response(command: cmd, response: buf);
      return buf;
    }
  }

  if (info_t == INFO_SSH)
  {
    if (isnull(timeout))
    {
      timeout = 120;
    }
    return ssh_cmd(cmd: cmd, timeout: timeout, nosudo: nosudo,
                   force_priv_escl: force_priv_escl);
  }

  if (info_t == INFO_RSH)
  {
    return send_rsh(login: login, port: port_g, cmd:cmd);
  }
  if (info_t == INFO_REXEC)
  {
    return send_rexec(login: login, pass: pass, port: port_g, cmd:cmd);
  }

  if (info_t == INFO_TELNET)
  {
    send(socket: sock_g, data:
      # Yes! Two spaces (or more) are necessary
      'echo NESSUS  START; ' +  cmd + ' 2>/dev/null; echo NESSUS  END\r\n');
    # But just one space here!
    buf = recv_until(socket: sock_g, pattern: 'NESSUS END');
    #debug_print('buf=>>>\n', buf, '<<<\n');
    recv_until(socket: sock_g, pattern: '[%$#>] ');
    # Only one space here!
    buf = strstr(buf, 'NESSUS START');
    #debug_print('buf=>>>\n', buf, '<<<\n');
    c = buf - 'NESSUS START';
    while (c[0] == '\r' || c[0] == '\n' || c[0] == ' ' || c[0] == '\t')
      c = substr(c, 1);
    c = chomp(c - 'NESSUS END');
    #if (c == buf) debug_print('info_send_cmd: could not extract command output from: ', buf);
    #debug_print('c=>>>\n', c, '<<<\n');
    return c;
  }

  #log_print('info_send_cmd: unhandled case info_t=', info_t, ' - cmd=', cmd, '\n');
  return NULL;
}

