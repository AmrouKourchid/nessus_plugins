#TRUSTED 6d1ae37f2ab80b510bcb4ab876b5469d48ee95f3a5c4abb75ce43a17d0b6b113be5bdfdd17cc2d30fe848130ff66e642567877843141c249d4a552d2d52b0eec786ea791ea6f26fe84650c874a968e2238b401f6f81eef9a50910c8e6fa5fd006c519ef128b418c6350c0ba181212703f4769757e75342ea0aa29df6da63a06a4d3b4b3fdcbe951252dbc1ff21382cbacfde7a3e7a25f9504f5ceb1a330c2de4d685f384689b55558971f7fa6f109945eb392e1d773a8799a9de37b055ac36fccddfe6130982ca7076def0ad21eee290cdf7b57492c50e3f2429b6725975bd3cfa922c3aff882459b15a317e5c9c257c3a07b6c6ec203f1425e824017f5be764f1ca98df0b7ada94071f60313fb9f9dcd4b8880ea6dd8a884febae5a39d183c38ea17e37192c2f87ab6f1db529f3d44e13803cd81fe5cb8047dc96c425e21e09e195156bf2ca1e3cba4a7940524832c10a3ee6d6519313103b61bd5cbfacaacf09eb04e8df8574b696e1a07fc1aee75e2034d3d5653817e2a4b69c4fc0032c307cdec1ce442e63eb5f3598e23faac23a54358d01037dffc4ea3475383d2e5b20b9b11c460066fb9244b473b78149516534d4fe3846df29bab84833f1a8b3f2b3c16ccb0bf4488daee475df62c7f30c47e1512b854e8962519752cfa8980e4573da74f0e96ef81c8706bbc1f170ca3ca62288fa48c5f9e595380683ad2853f539
#TRUST-RSA-SHA256 098f01a0e9f87beb61e9c5b413f9b6e6e9e6a6d8f232b5c0940d61c7f514552624554a2761bbc0ce262ea8b01492773fc7b9feb7b4b8cdd54ecf9b9406e3e79893046fd178b9687ea082ecb0113ae3b58e3c6a2a22064e2105e31dcff04705bea8b63d6c7a0faf8f0c39beb8e8dcf302f708953583d96104471fcd9a54a0fdbfa72786b6ec7b8e27ea652256d3ebe3f29c60d2f00757217f30477a6b4c4d47ca10748aa8285c257e6bbf0f0cf2d22220eb3c831091507d7302d3fa2ee4d2a2611d89f7e8159694c168423fc719176425b8225d1147cd08a89e288d3c2d7385f4196221b82028d7eae481ace481219a30f4aecc3054f28d7da37805c212fcdd3b3194ecc0f429f7e4aa9e798cfc1c730acb9c53cb6a592b915f38c36a182e8878287680c3d21cf2f144518b4405f25e1ca986c7eaee157834333091ab5d984560f0e5b3eb1b8f81baaf2affe055e5b9e2e407f2854766a767ae52d04657c77eeb749e383c48e8a2d0f36ecc20d0ed507a345bc58603d10007d925ddbe0d0965606447f102d1147302a3ef57169be23c0d11edb2d96abb291ee8ceeed84aa61f19489abdbeb2e734ee82bbe409e11daa953cd7a94965990d39b64e5bd079928e69f79b3e99fe2bed0e9ee5953a9ca479d25a24f0e418e32f873f5d35388251438f197400066b6533c48e8839864ca077be369cc2ffdcb560ce2c43d810b998bb3c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97993);
  script_version("1.57");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_name(english:"OS Identification and Installed Software Enumeration over SSH v2 (Using New SSH Library)");
  script_summary(english:"Gathers OS and installed software information over SSH.");

  script_set_attribute(attribute:"synopsis", value:
"Information about the remote host can be disclosed via an
authenticated session.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote host using SSH or local
commands and extract the list of installed packages.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_settings.nasl", "clrtxt_proto_settings.nasl");
  script_dependencies("os_fingerprint_ssh_netconf.nasl", "ssh_check_compression.nasl", "satellite_settings.nbin");
  script_dependencies("vmware_installed_patches.nbin", "vmware_installed_vibs.nbin");
  script_dependencies("ibm_tem_get_packages.nbin", "ssh_rate_limiting.nasl", "vmware_vcenter_collect.nbin");
  script_dependencies("symantec_altiris_get_packages.nbin", "satellite_6_get_packages.nbin");

  script_timeout(20*60);
  exit(0);
}

include("datetime.inc");
include("string.inc");
include("byte_func.inc");

include("ssh_get_info2.inc");
include("ssh_func.inc");
include("ssh_lib.inc");

include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("lcx.inc");

USE_SSH_WRAPPERS = TRUE;

start_time = gettimeofday();

# sleep for IOS-XR
sleep(1);
enable_ssh_wrappers();

use_hostlevel = FALSE;
var proto = NULL;
var port = NULL;
var user = NULL;

var timediff;

if (check_for_alternate_data_sources())
{
  security_note(port:0, extra:report);
  exit(0);
}

if(try_local_login())
{
  use_hostlevel = TRUE;
  proto = lcx::PROTO_LOCAL;
  report = '\nNessus can run commands on localhost to check if patches are applied.\n';
}
else
{
  var ssh_supplied, clrtxt_supplied;
  var disallowed_login, disallowed_login_error, disallowed_login_errors, error_list;
  # Check first to see if any credentials have been supplied
  if (
    !empty_or_null(get_kb_item("Secret/SSH/password")) ||
    !empty_or_null(get_kb_item("Secret/SSH/kdc_hostname")) ||
    !empty_or_null(get_kb_item("Secret/SSH/privatekey"))
  )
    ssh_supplied = TRUE;

  if (!empty_or_null(get_kb_item("Secret/ClearTextAuth/login")))
    clrtxt_supplied = TRUE;

  if (!ssh_supplied && !clrtxt_supplied)
    exit(0, "No SSH or cleartext credentials were supplied.");

  if(!empty_or_null(get_kb_item("SSH/disallowed_login_id")))
  {
    disallowed_login = TRUE;
    disallowed_login_error = NULL;
    disallowed_login_errors = get_kb_list(sshlib::SSH_LIB_KB_PREFIX + 'disallowed_login_id/error');
    if (!empty_or_null(disallowed_login_errors))
    {
      error_list = make_list(disallowed_login_errors);
      disallowed_login_error = '  - ' + join(error_list, sep:'\n  - ');
    }
  }

  var login_res = FALSE;
  var session;
  if (ssh_supplied)
  {
    # Remove any previous try_ssh_kb_settings_login() failure so login
    # will be tried again
    var prev_fail_kb = sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed";
    if (get_kb_item(prev_fail_kb))
    {
      dbg::detailed_log(
        lvl:2,
        src:SCRIPT_NAME,
        msg:"try_ssh_kb_settings_login() previously failed. Removing failure and trying again.");
      rm_kb_item(name:prev_fail_kb);
    }

    session = new("sshlib::session");
    login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:TRUE, force_none_auth:TRUE);
    sleep(1);
  }

  if(!login_res)
  {
    use_hostlevel = FALSE;
    if (clrtxt_supplied)
    {
      #    not implemented in hostlevel_funcs.inc
      #    login_method = "RLOGIN";
      #    use_hostlevel = try_rlogin();

      var login_method = "RSH";
      proto = lcx::PROTO_RSH;
      use_hostlevel = try_rsh_login();

      if(!use_hostlevel)
      {
        login_method = "REXEC";
        proto = lcx::PROTO_REXEC;
        use_hostlevel = try_rexec_login();
      }

      if(!use_hostlevel)
      {
        login_method = "TELNET";
        proto = lcx::PROTO_TELNET;
        use_hostlevel = try_telnet_login();
      }
    }

    var exit_message;
    if(!use_hostlevel && disallowed_login)
    {
      timediff = timeofday_diff(start:start_time, end:gettimeofday());
      exit_message = 'The host requested that login be performed as a different user:\n' + disallowed_login_error;

      lcx::log_issue(type:lcx::ISSUES_SVC, msg:exit_message, proto:lcx::PROTO_SSH, port:session.port);

      if(typeof(session) == 'object')
        session.close_connection();
      exit(1, exit_message + '\nRuntime : ' + timediff + ' seconds.');
    }
    else if(!use_hostlevel)
    {
      timediff = timeofday_diff(start:start_time, end:gettimeofday());
      if(typeof(session) == 'object')
      {
        port = session.port;
        session.close_connection();
      }
      exit_message = 'Unable to login to remote host with supplied credential sets.';
      var try_kb_login_errors = get_kb_list(sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login/error");

      if (!empty_or_null(try_kb_login_errors))
      {
        error_list = make_list(try_kb_login_errors);
        exit_message += '\nErrors:\n  - ';
        exit_message += join(error_list, sep:'\n  - ');
      }

      if ("password" >< exit_message && "must be changed" >< exit_message)
        lcx::log_issue(type:lcx::ISSUES_ERROR, msg:exit_message, proto:lcx::PROTO_SSH, port:port);
      else
        lcx::log_issue(type:lcx::ISSUES_SVC, msg:exit_message, proto:lcx::PROTO_SSH, port:port);

      exit_message += '\nRuntime : ' + timediff + ' seconds.';
      exit(1, exit_message);
    }

    report = '\nIt was possible to log into the remote host via ' + login_method + '.\n';
    port = port_g;
    user = login;
    lcx::log_auth_success(proto:proto, port:port, user:user, clear_failures:TRUE);
  }
  else
  {
    # Gather / report session variables before closing session
    report = '\nIt was possible to log into the remote host via SSH using \''
             + session.login_method + '\' authentication.\n';

    rm_kb_item(name:"Host/Auth/SSH/" + session.port + "/Failure");
    report_xml_tag(tag:"ssh-auth-meth", value:session.login_method);

    proto = lcx::PROTO_SSH;
    port  = session.port;
    user  = session.user;

    host_info_key_val['remote_ssh_banner'] = session.remote_version;
    host_info_key_val['remote_ssh_userauth_banner'] = session.userauth_banner;
    host_info_key_val['kb_connection_id'] = session.get_kb_connection_id();

    var escl_method = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + host_info_key_val['kb_connection_id'] + "/escalation_type");
    var cred_type = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + host_info_key_val['kb_connection_id'] + "/cred_type");
    var auth_method = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + host_info_key_val['kb_connection_id'] + "/login_method");

    session.close_connection();

    if(disallowed_login)
      report +=
        '\nNote, an attempt was made to log in with a different credential set in' +
        '\nthe policy but the host returned an error : ' +
        '\n' + strip(disallowed_login_error) + '\n';

    set_kb_item(name:'HostLevelChecks/proto', value:'ssh');
    report_xml_tag(tag:"local-checks-proto", value:"ssh");

    set_kb_item(name:"HostLevelChecks/login", value:user);
    report_xml_tag(tag:"ssh-login-used", value:user);

    if(!isnull(cred_type))
      replace_kb_item(name:"HostLevelChecks/cred_type", value:cred_type);
    if(!isnull(auth_method))
      replace_kb_item(name:"HostLevelChecks/auth_method", value:auth_method);

    sshlib::set_support_level(level: sshlib::SSH_LIB_SUPPORTS_LOGIN);

    dbg::detailed_log(src:SCRIPT_NAME, lvl:2, msg:'Login success! Associated escalation method to try: ' + escl_method);

    var exec_tried = FALSE;
    var ret;

    if(!escl_method || escl_method =~ "(?:Nothing|[Nn]one)")
    {
      dbg::detailed_log(src:SCRIPT_NAME, lvl:1, msg:'Trying exec checks.');

      ret = sshlib::try_ssh_exec(port:port, cmd_list:exec_checks);

      exec_tried = TRUE;
      if(ret[0])
      {
        dbg::detailed_log(src:SCRIPT_NAME, lvl:1, msg:'Exec checks successful. Using exec method to run commands.');
      }
      else
      {
        dbg::detailed_log(
          src:SCRIPT_NAME,
          lvl:1,
          msg:'The exec checks failed with the following error.',
          msg_details:{"Error":{"lvl":1, "value":ret[1]}});

        #Reset command values for devices that don't support exec
        var new_host_info_key_val = {};
        for(var key in host_info_key_val)
        {
          if("host_not" >!< key && "_unrecognized" >!< key && "_error" >!< key)
            new_host_info_key_val[key] = host_info_key_val[key];
        }

        host_info_key_val = new_host_info_key_val;
      }

    }
    if(sshlib::get_support_level() < sshlib::SSH_LIB_SUPPORTS_COMMANDS)
    {
      var report_backup1 = report;

      ret = sshlib::try_ssh_shell_handlers(port:port, shell_handlers:handler_list, cmd_list:shell_handler_checks);
      if(ret[0])
      {
        dbg::detailed_log(src:SCRIPT_NAME, lvl:1, msg:'Found working shell handler, using it to run commands.');

        if("command was successful without privilege escalation" >< ret[1])
        {
          var report_backup2 = report;
          report = report_backup1;

          var seperator = '\n';
          var additional_info = " an unknown reason. ";
          if(!isnull(ret[2]) && strlen(ret[2]) > 0)
          {
            additional_info = ' the following reason :\n\n' + ret[2] + '\n\n';
            seperator = " ";
          }

          dbg::detailed_log(src:SCRIPT_NAME, lvl:2, msg:'No escalation was used, trying exec checks in case one works.');
          ret = sshlib::try_ssh_exec(port:port, cmd_list:exec_checks);
          if(ret[0])
          {
            dbg::detailed_log(src:SCRIPT_NAME, lvl:1, msg:'Exec check successful, using it instead of the shell handler.');
            rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "shell_handler");
          }
          else
          {
            dbg::detailed_log(
              src:SCRIPT_NAME,
              lvl:2,
              msg:'No exec check worked, keeping the shell handler.',
              msg_details:{"Reason":{"lvl":2, "value":ret[1]}});
            report = report_backup2;
          }

          # Last use of escl_method in this plugin and only used for reporting, safe to modify.
          if (escl_method == "su_sudo")
            escl_method = "su+sudo";

          report += '\n' + "Note, though, that an attempt to elevate privileges using '" + escl_method + '\' failed\n' +
                    'for' + additional_info + 'Further commands will be run as the user' + seperator + 'specified in the scan policy.\n';
        }
        else
        {
          if(!isnull(escl_method))
            replace_kb_item(name:"HostLevelChecks/escl_method", value:escl_method);
        }
      }
      else
      {
        dbg::detailed_log(
          src:SCRIPT_NAME,
          lvl:1,
          msg:'The shell handler checks failed with the following error.',
          msg_details:{"Error":{"lvl":1, "value":ret[1]}});
      }
    }
    if(sshlib::get_support_level() < sshlib::SSH_LIB_SUPPORTS_COMMANDS && !exec_tried)
    {
      ret = sshlib::try_ssh_exec(port:port, cmd_list:exec_checks);
      exec_tried = TRUE;

      if(ret[0])
      {
        dbg::detailed_log(src:SCRIPT_NAME, lvl:1, msg:'Exec checks successful. Using exec method to run commands.');
        report += '\n' +
          "Note, though, that an attempt to elevate privileges using '" +
          escl_method + '\' failed\n' +
          'because a compatible shell handler was not found. Further commands\n' +
          'will be run as the user specified in the scan policy.\n';

        rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + host_info_key_val['kb_connection_id'] + "/escalation_type");
      }
      else
      {
        dbg::detailed_log(
          src:SCRIPT_NAME,
          lvl:1,
          msg:'The exec checks failed with the following error.',
          msg_details:{"Error":{"lvl":1, "value":ret[1]}});
      }
    }
  }
}

if(typeof(session) == 'object') session.close_connection();

var local_checks_hostlevel = FALSE;
if(use_hostlevel)
{
  if(info_t == INFO_LOCAL)
    ret = try_hostlevel(cmd_list:local_scanner_checks);
  else
    ret = try_hostlevel(cmd_list:hostlevel_checks);

  if(ret[0])
  {
    if (get_kb_item("Host/local_checks_enabled"))
    {
      local_checks_hostlevel = TRUE;
      set_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "local_checks_hostlevel", value:TRUE);
    }
    dbg::detailed_log(
      src:SCRIPT_NAME,
      lvl:1,
      msg:'Found working shell handler: ' + get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "/shell_handler") + '_shell_handler.');
  }
  else
  {
    dbg::detailed_log(src:SCRIPT_NAME, lvl:1, msg:'The host level checks failed to identify the host.');
  }
}

if(failure_kb_msg)
{
  if (!failure_kb_type)
    failure_kb_type = lcx::ISSUES_ERROR;
  lcx::log_issue(type:failure_kb_type, msg:failure_kb_msg, proto:proto, port:port, user:user);
}

if(sshlib::HOST_SUPPORT_LEVEL != sshlib::HOST_SUPPORTS_LOCAL_CHECKS && !local_checks_hostlevel)
{
  var failure_type = NULL;
  var failure_msg = NULL;
  switch (sshlib::HOST_SUPPORT_LEVEL)
  {
    case sshlib::HOST_LOCAL_CHECKS_UNAVAILABLE:
      set_kb_item(name:"HostLevelChecks/unavailable", value:SCRIPT_NAME);
      failure_msg =
        'We are able to identify the remote host.'+
        '\nOS security patch assessment is NOT supported.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_INFO;
      break;
    case sshlib::HOST_LOCAL_CHECKS_ERROR:
      failure_msg =
        'We are able to identify the remote host, but encountered an error.'+
        '\nOS Security Patch Assessment is NOT available.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_ERROR;
      break;
    case sshlib::HOST_SUPPORTS_COMMANDS:
      failure_msg =
        'We are able to run commands on the remote host, but are unable to'+
        '\ncurrently identify it in this plugin.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_INFO;
      break;
    case sshlib::HOST_SUPPORTS_LOGIN:
      failure_msg =
        'The remote host is not currently supported by this plugin.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_INFO;
      break;
    default:
      # should not be possible to get this far, but handle just in case
      failure_msg = 'Unable to run commands on the remote host.';
      report += '\n' + failure_msg + '\n';
      failure_type = lcx::ISSUES_INFO;
  }

  if(!failure_kb_msg && failure_msg)
    lcx::log_issue(type:failure_type, msg:failure_msg, proto:proto, port:port, user:user);
}

timediff = timeofday_diff(start:start_time, end:gettimeofday());
report += '\nRuntime : ' + timediff + ' seconds\n';
lcx::log_report(text:report);
security_note(port:0, extra:report);
exit(0);

