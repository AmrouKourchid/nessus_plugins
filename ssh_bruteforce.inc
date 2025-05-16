#TRUSTED 7f08baa2380bd3a60c7a19515bb59960e28c3aa4c662ac8f8288bf1b3b894af7b2c4446c00f8566629f2f644084be04a52be061718b9373dab3ca17be231b1c7d385fdf175957def7aad76ee5ff86e682b33255ebb8eb0b440db8a8a3de1759367e4652a643e7b2b3f90b263e650b02fae7d98bf1b383262966f2a5a52336fca1b1ee96a30b5aa50a3081c6d75f64594cb3f0dc45c0bc6ee78b9946f7e1a29193666532bff4673c229406f3a66a89fb8ced345fcff9ae578eeb9fce12a1403bb06f54b56e9aa6fd6bb26639e486086a02eeb45a38df1e8311bf70288dfb14a61580d6e468746de301542fe4dfbe92fc14c61d656ac2d4296c2c643826355e986a5fc1a27dc7f096adbee6cdd40627f757739f6c8f1492056679317948bdd6c28aa6631d031c8861b9ce7e8b53429e8e4073e798ac3581f441098111bffd4e10fe0dc5168fcab557a5492583a3bada8c74a616f720e9dd3c2f077228710c997fcd55a0e7ea2d4d3fa58d04dec90c5401c80f66a04720bbd4d5f42a3530a2e164107f5130ebff0d5cef82ac6b3104789c101dbe4ea84fb85e7fb8a16977529637960139930a59ef574e438e2ac3d2c9100703245570a6deb4b08626bf2460aefc79f520459adaa5d662bab883872e47cf0d76690d831557db0a540c43d5031b64b1bf8a8d8e46fdd5a512f1b266114c4eac17c1eeabad4d0889f34bf68090cb705
#
# (C) Tenable Network Security, Inc.
#
# Revision: 1.3
#

include("compat_shared.inc");
include("debug.inc");
include("ssh_lib.inc");
include("spad_log_func.inc");

global_var prompt_after_login = FALSE;
global_var last_buffer_update_ts, cur_buf_change_counter;
global_var inactivity_timeout = 5;
global_var session_error = FALSE;
global_var session_reopen_failure = FALSE;

global_var ssh_obj, starttime;

object bruteforce_pci
{
  var server_failures = 0;
  var auth_failures = 0;
  var affected = FALSE;
  var report = "";
  var server_failed = FALSE;
  var scan_timeout = FALSE;

  public function incr_server_failures() { server_failures += 1; }
  public function incr_auth_failures() { auth_failures += 1; }
  public function set_affected(val) { affected = val; }
  public function append_report(val) { report += val; }
  public function set_server_failed(val) { server_failed = val; }
  public function set_scan_timeout(val) { scan_timeout = val; }
}

function cb_on_login_prompt_or_inactivity(session, channel)
{
  var last6;
  if(strlen(channel.data_buf) == 0) last6 = " ";
  else if(strlen(channel.data_buf) < 6) last6 = channel.data_buf;
  else last6 = substr(channel.data_buf, strlen(channel.data_buf) - 6);

  var buf = tolower(channel.data_buf);
  if (
    "domain (? for all)" >< buf ||
    "invalid login" >< buf ||
    ( "ogin:" >< buf && "last login: " >!< buf ) ||
    "password:" >< buf ||
    "user:" >< buf ||
    "username:" >< buf ||
    "user name:" >< buf ||
    "access denied" >< buf ||
    "must be changed" >< buf ||
    "permission denied" >< buf
  )
  {
    prompt_after_login = TRUE;
    return TRUE;
  }
  # if we are sitting at a prompt return for success
  if ("#" >< last6 || ">" >< last6 || "$" >< last6 || "%" >< last6) return TRUE;
  if(channel.state == sshlib::CHANNEL_STATE_CLOSED) return TRUE;
  if(channel.buf_change_counter != cur_buf_change_counter)
  {
    cur_buf_change_counter = channel.buf_change_counter;
    last_buffer_update_ts = unixtime();
  }
  else if ((unixtime() - last_buffer_update_ts) > inactivity_timeout)
  {
    return TRUE;
  }
  return FALSE;
}

function check_for_post_login_prompt(&session, timeout)
{
  var fn = "check_for_post_login_prompt: ";
  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Opening a shell to check for a secondary login or password prompt.');

  # Just use the sh_shell_handler for the pty options
  var channel = session.open_shell(shell_handler:new("sshlib::sh_shell_handler"), skip_check_shell:TRUE);
  if (!channel)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Failed to open a shell.');
    return FALSE;
  }
  # Receive to check for a login or password prompt from the shell
  prompt_after_login = FALSE;
  if (!timeout) timeout = 20;
  last_buffer_update_ts = unixtime();
  session.sshrecv_until(
    end_states     : make_list("SOC_CLOSED"),
    check_callback : @cb_on_login_prompt_or_inactivity,
    channel        : channel,
    cmd_timeout    : timeout
  );
  if (prompt_after_login)
  {
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Found login prompt after session.login(). Login attempt failed. Testing next credential set.");
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

function try_ssh_login(&session, user, pass, port)
{
  if (!session)
  {
    session_error = TRUE;
    return FALSE;
  }
  session_reopen_failure = FALSE;
  session_error = FALSE;
  var extra = { "username":user, "password":pass  };
  var ret = session.login(method:"password", extra:extra, save_login:FALSE);
  # If login failed, see if we need to reconnect and retry
  if ( !ret &&
       ( session.last_packet.type == sshlib::PROTO_SSH_MSG_DISCONNECT ||
      session.cur_state.val == "SOC_CLOSED" ) )
  {
    if (!port)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Server disconnected, port was not passed to reconnect.');
      session_error = TRUE;
      return FALSE;
    }
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Server disconnected, reconnecting.');
    session.close_connection();
    delete(session);

    session = new("sshlib::session");
    if(!session.open_connection(port:port))
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Failed to re-open connection.');
      session_error = TRUE;
      session_reopen_failure = TRUE;
      return FALSE;
    }
    ret = session.login(method:"password", extra:extra, save_login:FALSE);
  }

  if (!ret)
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Login failed for user "'+user+'", password "'+pass+'".');
  else
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Login succeeded for user "'+user+'", password "'+pass+'".');

  return ret;
}

function check_username(username, port, passlist)
{
  local_var session, ret, pass;
  local_var result = 0;
  session = new("sshlib::session");
  if(!session.open_connection(port:port)) return 0;
  if(!session.auth_method_supported(method:"password", username:username))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Authentication method "password" not supported for user "'+username+'".');
    session.close_connection();
    return result;
  }
  foreach pass (passlist)
  {
    ret = try_ssh_login(session:session, user:username, pass:pass, port:port);

    if (!ret)
    {
      if (session_reopen_failure)
      {
        ssh_obj.incr_server_failures();
      }
      else
      {
        ssh_obj.incr_auth_failures();
      }
      # At least 10% and 20 total server drops, possible fail2ban on server (brute force will be impossible)
      if (ssh_obj.server_failed ||
          ssh_obj.server_failures >= 20 && ssh_obj.server_failures * 10 >= ssh_obj.auth_failures)
      {
        ssh_obj.set_server_failed(val:TRUE);
        session.close_connection();
        return result;
      }

      # Exit on time exceed 4 hours, possible scan interference
      if (ssh_obj.scan_timeout ||
          unixtime() - starttime >= 14400)
      {
        ssh_obj.set_scan_timeout(val:TRUE);
        session.close_connection();
        return result;
      }
      continue;
    }
    # check for post login prompt for devices like Cisco WLC and SonicWall
    # if found login prompt, assume login failed and continue testing creds.
    if (check_for_post_login_prompt(session:session)) continue;

    ssh_obj.set_affected(val:TRUE);
    ssh_obj.append_report(val:'\n  Login : ' + username +
              '\n  Pass  : ' + pass +
              '\n');
    result ++;
    if (!thorough_tests)
    {
      session.close_connection();
      return result;
    }
  }
  session.close_connection();
  return result;
}
