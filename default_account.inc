#TRUSTED 69bb5a50f7179bdea9b3fc9651ecc0d1d907587223e2bdb5938a6ceeda705217a8f2ad16e09ff1e21dccf944feeafb5da1ad455c6aa0782f6e02f18c8a5d0f1019b35374cc0d6549bf1d9a3833559329f8406d5d69ee0d6a144c236a4a5b136f8476604a5f072c88be0bc61863d9fecfba52ca71e671c3296bbff716ad53250c381319b85ef30f2bb82db321841dfcddf8e4b707cf3fc0a3e275dfaa2d1530b45af61319e24d1bbc8f37c50ff5c07819a1495092c45aa3e42cb44fb30d18e4e797c457ab8c34f5b641666addab7a4b3c546ae4f24b9f14a676f415ff36a9731c5346d7376cf48f78369741e4967d8b0b8232758f12cba3ed7667f614d7a7f91e460e4975022f298b42888053ad002291538ba06ad65d4b22f4a8f42e18c779022687837f28efa6d4996a6636739f79de8dc98edb79e43cb9d0319ec1ff8e833b3352353d5ce6c8a36eb6f9ba273fd48e463070adfcb92774227d879f4ea01f506733ce29e627d49ed188cf522db5e35e9b3349cdebe17738f779f492d4a72c00d9d15b3f7244fb96f7e40b1090ee00c598319cc29da1262c6a4ce32ec019173315a575c03c983b6e15cbc3b3e3cb169e2e4126f5cab32b123f463bd83450ce118caf70610d59fb0bf63bf622986896734fc8b56dd2e2eef6510c4faef850d48bf26cf5f311a91ee1329ffc7f3cfa47192c389b08639ad009e942d94d90a70424
#TRUST-RSA-SHA256 07912630d89b46c6a4f98a6ecd27155a05c2d0eed6662de3a582cbc5307b87a47336f28151601bf1fe74e8f09d8f92f3f7f5d03613f8a698e11a33b11251e4068b449442e2b87d2e99caf29581cc62e83b4723c28cb127e13c299d22de80c4a6ee2197029b0da5723201aa7269a51f3838a7c2a92493d6e8cea8e75202a796240ad197c268599a327c2cf37b6cffffe7c1b1e22bb643cc160de30b0d3518b9161dbcc75918b9ef036382ae3504a1f0613586f7dbdfba506f376d6d3399dd0ff461d99856dbec5df39f68110b56e4eeafe96bb4cb7115ad652a309a0cef19bcc3c9a41f257a4a71b349a7cf950a69f4450e9832dfdf492a3ca9c0144a7e08a215c360a1acac657384a32a768ed4e8cbb1f29a2f2bebd63c5e121c68a2aac3ea04ce02fed451a124dc74220515d05b51a78aed208b728ca658debf37bf4019d9101e3ba0b3b3f17adb3932c354c75c61e28579177510ea50f98056931ef9fce9b1a4993a47cd642a19a609e3b684ef33963ee1b7e1af30c7dfa49efc58dbaf5151ddd527c5a5f1a5b470c7dc4c6d0ca03ca00bbaa42578f2928f7b4e99b078ef5211316d2caaf1d8320492173e0654e13fb8b43506126de936f8136de64725c000eec7ecde38186c16a88e519b0fecd79b688bdb2828e25182db37e7b308d47805afa24cec0951637b4c0d99e0b9052b9b4258e4cac39fcff6611f19f07cb25c6b
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# This file implements (or will implement) various ways of determining if
# an account is valid
#
# @NOGPL@
#
# default_account.inc
# Revision: 1.44
#

include("compat_shared.inc");
include("byte_func.inc");
include("telnet_func.inc");
include("ssh_func.inc");
include("ssh_globals.inc");
include("ssh_lib.inc");

enable_ssh_wrappers();

global_var _login_text;
#
# Private functions
#

function default_account_report(cmd)
{
 local_var retval;
 if(isnull(cmd))
 {
   if("uid=" >< _login_text)
     cmd = 'id';
 }

 if ( isnull(_login_text) || strlen(_login_text) == 0 ) return NULL;
 if (!isnull(cmd))
 {
  retval = '\n' + "It was possible to execute the command '" + cmd + "' on the remote host :" +
           '\n\n';

  # don't add formatting spaces for multi-line command output
  if('\n' >< chomp(_login_text))
    retval += _login_text;
  else retval += '  ' + _login_text;

  return retval;

 }
 else return '\n' + "Once logged in, we obtained the following :" +
             '\n' +
             '\n' + _login_text;
}

function _check_telnet(port, login, password, login_regex, password_regex, cmd, cmd_regex, out_regex_group)
{
 local_var soc, res, res2, ch, item;
 soc = open_sock_tcp(port);
 if(!soc)return(0);

 if(!isnull(cmd))
 {
   if(isnull(cmd_regex))
     exit(1, 'Missing required cmd_regex argument.');
 }

 res = telnet_negotiate(socket:soc);

 if(!isnull(login))
 {
   if (isnull(login_regex)) login_regex = "ogin:";

   res += recv_until(socket:soc, pattern:login_regex);
   if ( ! res ) exit(0, 'A login prompt was not found while connecting to port '+port+'.');

   res = '';
   send(socket:soc, data:login + '\r\n');
 }

 if (isnull(password_regex)) password_regex = "word[ ]*[:>]";
 res += recv_until(socket:soc, pattern:password_regex);

 if (res)
 {
   # nb: NULL is not the same as an empty password, and a
   #     Telnet server may display a password prompt even
   #     when the account has an empty password.
   if (isnull(password))
   {
     close(soc);
     return 0;
   }
   send(socket:soc, data:password+'\r\n');
 }
 else
 {
   # nb: If there was no password prompt but the check
   #     includes a password, it's a failure.
   if (strlen(password))
   {
     close(soc);
     return 0;
   }
 }

 # nb: Some servers prompt for a terminal type.
 res = recv_until(socket:soc, pattern:'Terminal type\\?');
 if (res)
 {
   if ('Terminal type?' >< res) send(socket:soc, data:'vt100\r\n');
 }

 if(!isnull(cmd))
   send(socket:soc, data:cmd +'\r\n');
 else
   send(socket:soc, data:'id\r\n');

 if(!isnull(cmd))
 {
   ch = recv(socket:soc, length:1);
   while(strlen(ch) != 0)
   {
     res += ch;
     ch = recv(socket:soc, length:1);

     if(res =~ cmd_regex)
     {
       if(isnull(out_regex_group))
       {
         _login_text = res;
       }
       else
       {
         item = pregmatch(pattern:cmd_regex, string:res);
         if(isnull(item))
           return 0;
         _login_text = item[out_regex_group];
       }
       close(soc);
       return 1;
     }
   }
 }
 else
 {
   res += recv_until(socket:soc, pattern:"uid=");
   if ("uid=" >< res)
   {
     res2 = recv_until(socket:soc, pattern:'gid.+\\r');
     if (res2)
     {
       res = "uid=" + chomp(res2);
       _login_text = res;
     }
     close(soc);
     return 1;
   }
 }
 close(soc);
 return 0;
}

#-------------------------------------------------------------------#

function check_account(login, password, unix, check_mocana, cmd, cmd_regex, out_regex_group, nosh, nosudo, noexec, nosetup, check_telnet, port, svc)
{
  local_var ret;

  checking_default_account_dont_report = TRUE;

  if (  get_kb_item("global_settings/supplied_logins_only") ) return 0;
  if ( isnull(unix) || unix == TRUE )
  {
    if (  get_kb_item("login/unix/auth/broken") ) return 0;
  }
  else if (  get_kb_item("login/auth/broken") ) return 0;

  if(isnull(check_telnet)) check_telnet = FALSE;

  if (svc == "telnet" )
  {
    if (!check_telnet &&
        login != "root" &&
        password &&
        (
          !get_kb_item("global_settings/thorough_tests") ||
           get_kb_item("global_settings/thorough_tests") != "yes")
        ) return 0;
    else ret = check_account_telnet(login:login, password:password,
                                    unix:unix, cmd:cmd,
                                    cmd_regex:cmd_regex,
                                    out_regex_group:out_regex_group,
                                    port:port);
  }
  else ret = check_account_ssh(login:login, password:password,
                               unix:unix, check_mocana:check_mocana,
                               cmd:cmd, cmd_regex:cmd_regex,
                               out_regex_group:out_regex_group,
                               nosh:nosh, nosudo:nosudo, noexec:noexec,
                               nosetup:nosetup, port:port);

  if(ret) return ret;
}

##
# Uses the provided login information to attempt to connect via SSH
# to the provided port.
#
# @return port, if vulnerable.
##
function check_account_ssh(login, password, unix, check_mocana, cmd,
                           cmd_regex, out_regex_group, nosh, nosudo,
                           noexec, nosetup, port)
{
  local_var ret, banner, soc, res, item;
  local_var payload, remote_channel;
  if ( defined_func("bn_random") )
  {
    # Prefer login thru SSH rather than telnet
    if ( ! port ) port = 22;

    banner = get_kb_item("SSH/banner/" + port);
    if (!banner)
    {
      banner = get_kb_item("ssh/banner/" + port);
      if (banner) banner = chomp(banner);
    }

    # GoodTech SSH server does not respect SSH protocol ...
    # nor does Mocana's (at least as used in AMX devices).
    if (banner &&
        "cryptlib" >!< banner &&
        (
          "SSH-2.0-Mocana SSH" >!< banner ||
          check_mocana == TRUE
        )
    )
    {
      _ssh_socket = open_sock_tcp(port);
      if ( _ssh_socket )
      {
        ret = ssh_login(login:login, password:password);
        if ( ret == 0 )
        {
          if ( isnull(unix) || unix == TRUE || !isnull(cmd) )
          {
            if(!isnull(cmd))
            {
              if(isnull(cmd_regex))
              exit(1, 'Missing required cmd_regex argument.');
            }

            # Preserve current way of running commands.
            if (isnull(nosh)) nosh = TRUE;
            if (isnull(nosudo)) nosudo = TRUE;

            if(!isnull(cmd))
              ret = ssh_cmd(cmd:cmd, nosh:nosh, nosudo:nosudo,
                            noexec:noexec, nosetup:nosetup);
            else
              ret = ssh_cmd(cmd:'id', nosh:nosh, nosudo:nosudo,
                            noexec:noexec, nosetup:nosetup);

            if(!isnull(cmd))
            {
              if(ret =~ cmd_regex)
              {
                if(isnull(out_regex_group))
                {
                  _login_text = ret;
                }
                else
                {
                  item = pregmatch(pattern:cmd_regex, string:ret);
                  if(isnull(item))
                    return 0;
                  _login_text = item[out_regex_group];
                }
                ssh_close_connection();
                return port;
              }
            }
            else
            {
              if ( ret && "uid=" >< ret )
              {
                ssh_close_connection();
                _login_text = ret;
                return port;
              }
            }
            return 0;
          }

          #
          # Some SSH servers do not fully respect the SSH protocol - they
          # claim that password authentication succeeded, but then
          # they'll refuse any other command. The workaround here is to
          # open a SSH channel, as if we wanted to create an interactive session.
          #
          # Note that we do not use ssh_open_channel() but a stripped down version
          #
          payload = putstring(buffer:"session") + raw_int32(i:1) +
                    raw_int32(i:32768) + raw_int32(i:32768);
          send_ssh_packet(payload:payload, code:raw_int8(i:90));
          payload = recv_ssh_packet();
          if ( !isnull(payload) )
          {
            # Fix for tectia AIX
            if (ord(payload[0]) == 95)
            {
              payload = getstring(buffer:payload, pos:9);
              payload = recv_ssh_packet();
            }
            if ( !isnull(payload) && ord(payload[0]) == 91 )
            {
              remote_channel = ntol(buffer:payload, begin:5);
              payload = raw_int32(i:remote_channel) +
                        putstring(buffer:"pty-req") + raw_int8(i:0) +
                        putstring(buffer:"vt100") + raw_int32(i:80) +
                        raw_int32(i:24) + raw_int32(i:640) +
                        raw_int32(i:480) +
                        putstring(buffer:raw_int8(i:53) +
                                  raw_int32(i:0) + raw_int8(i:72) +
                                  raw_int32(i:0) + raw_int8(i:0));
              # SSH_MSG_CHANNEL_REQUEST == 98
              send_ssh_packet(payload:payload, code:raw_int8(i:98));
              payload = raw_int32(i:remote_channel) +
                        putstring(buffer:"shell") + raw_int8(i:0) ;
              # SSH_MSG_CHANNEL_REQUEST == 98
              send_ssh_packet(payload:payload, code:raw_int8(i:98));
              payload = raw_int32(i:remote_channel) +
                        putstring(buffer:'\n');
              send_ssh_packet(payload:payload, code:raw_int8(i:94));
              payload = recv_ssh_packet();

              while(!isnull(payload) &&
                    (
                      (ord(payload[0]) == 93) ||
                      (ord(payload[0]) == 95) ||
                      (ord(payload[0]) == 98))
                    ) payload = recv_ssh_packet();
              if ( ord(payload[0]) == 94 )
              {
                payload = getstring(buffer:payload, pos:5);
                _login_text = payload;
                if ("Domain (? for all)" >!< payload &&
                    "invalid login" >!< payload &&
                   ("ogin:" >!< payload ||
                    "Last login: " >< payload) &&
                    "User Name:" >!< payload &&
                    "Username:" >!< payload &&
                    "assword:" >!< payload)
                {
                  ssh_close_connection();
                  return port;
                }
              }
            }
          }
        }
        ssh_close_connection();
      }
    }
  }
}

##
# Uses the provided login information to attempt to connect via telnet
# to the provided port.
#
# @return port, if vulnerable.
##
function check_account_telnet(login, password, unix, cmd, cmd_regex, out_regex_group, port)
{
  local_var ret;
  if ( (!isnull(unix) && unix == FALSE) && isnull(cmd) ) return 0;
  if(!port) port = 23;

  if(get_port_state(port))
  {
    if ( isnull(password) ) password = "";
    ret = _check_telnet(port:port, login:login, password:password,
                        cmd:cmd, cmd_regex:cmd_regex,
                        out_regex_group:out_regex_group);
    if(ret) return port;
  }
}
