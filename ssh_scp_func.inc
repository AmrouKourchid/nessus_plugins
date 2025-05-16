#TRUSTED a07ffd18db45b296cc5eb225734540e9c4a29585691adcef48e8bebc9637be4779490bb676c3e6ecb7b121a4fa90feab438e821131416af0233dfe234bdc7e54a4e671b2a5924cf179f7870ef0584ee8782c03cfa21ba2c2f5a91a81f336ae24eb40a4e36217a0c5cec1dec8a5ca5bb2cfc30a90b1ce05fe3b5caf251d69857d2bcff7488a067ffc3b4334be9e5fa7c18d177a50697048c597e58acf02f8605a9e13d722ee4e76bb21787299a73a863341e98f455d5853b638270112df8a5db393f3f34fde394df58b8527695b1f9cb80b360a0be2d7a713e8a3a7d2ce96df37ffa124ff2b7e3e79497e8b6722dc62b32d0085c95c191cd15800aa455f90afb13039d5d5b4c12398efd66b248045f8842ad2bc61fe5134ee8b7cf4f1e9635b17690a5a70e40e8a215211895b848228f6e9913074b7239c7b931166bef14b1884341b06de78d60c84086df2b0d150374f538a23cc16087baecdfb80ceca9c074bf47a6bafb0821c2d9de37d8229a69d3106c60f0af926c6133c7142a9f8bb691a626379ff5c6f80fcb214ea02f3e094229e280a538e5d189c6ad5161370d3d39bc4ac9596a71a1f71d15abd01b43b424457659d41dd9a6a690e6e6675a706901fe138415be749e5bbfd1ea8d3251b7931c48e469a055e25313eb263ca428cb6dc93a18f16a2956272ac10c72343896c5506293d1cd5bbf010fb2b37c0b1a9a62a
#TRUST-RSA-SHA256 8473d24993b97fe3c4d7abd628a40e94cd8a3a97fedc7f806cec65a62c815d778317a8816367f336248e66707d5e190a21d44bb052c11a4e1834e620703b9f363134bf96295de80fc16eb386fe99cb5216a43264f32c5d3945f3742dad8d537d3a7f6dd29d44762f13de169c83d53a4898f2510f7c3939b651b1a9803b37c36fcfc732368873e4080873672c71edaa7493c607d6d84d74835ce4cd6e4869fac26413cc94c271a99c19f7c2dfc883c3f4a9890d9be5daed7fe20d7150ac7cc5adf7967d8c4d698dc15aabc756b61fcba7a888bc8d368807ae0d6827a0c6b79f245f7ccb4829226ab16c6518ce1c768e52dbe3fcd3e9f0af15e577695aa9da6c352582a74a03db282dd9990965fe4b0a313ae557b4001d189d130bbbc88710218de33648e94924c8195fad7065694c0195f177b086a4a656c6d51392598b3257ff97dd7b1fc50690597be33bbeb947c3b85a268af7434bb47137b2a1a325c8e973fe76de4d2fc581cefd6be87552c41f86a3f65c313d931bab703aa1d37c3722a4bd790211752fa9492a56372ab01ca1fe03f7d3369ae411a19e459fd7cffeec28c61777b2b1755a55f773e4b68e2b43088da1df51bf472d417e1786d852665b4fb19d92bb5806ca840ca504a3e7df3c00519d9612fec31940f9d752bb2f11e48cda60d44332aa359c821dead29cd7f58f434cc3b1ac43cc53a1f264437c9c6f73
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.5
#

include("compat_shared.inc");
include("byte_func.inc");
include("ssh_globals.inc");
include("ssh_func.inc");
include("ssh_lib.inc");

global_var ssh_scp_state;
global_var SSH_SCP_NEW, SSH_SCP_CHANNEL_OPEN, SSH_SCP_READ_INITED;
global_var SSH_SCP_WRITE_INIT, SSH_SCP_DONE, SSH_SCP_CLOSED, SSH_SCP_WRITE_DONE;
global_var SSH_SCP_SINK_OK, SSH_SCP_SINK_WARNING, SSH_SCP_SINK_ERROR;

SSH_SCP_NEW = 0;
SSH_SCP_CHANNEL_OPEN = 1;
SSH_SCP_READ_INITED = 2;
SSH_SCP_WRITE_INIT = 3;
SSH_SCP_WRITE_DONE = 4;
SSH_SCP_DONE = 5;
SSH_SCP_CLOSED = 6;


SSH_SCP_SINK_OK = 0;
SSH_SCP_SINK_WARNING = 1;
SSH_SCP_SINK_ERROR = 2;


ssh_scp_state = SSH_SCP_NEW;

##
# Initializes an SCP session over SSH
# @returns TRUE on success, FALSE on failure
##
function ssh_scp_init()
{
  local_var ret;
  if(ssh_scp_state != SSH_SCP_NEW)
    set_ssh_error(msg:"ssh_scp_init called under invalid state.");

  ret = ssh_open_channel();
  if (ret != 0)
  {
    set_ssh_error(msg:"Nessus failed to open a new SSH channel.");
    return FALSE;
  }
  ssh_scp_state = SSH_SCP_CHANNEL_OPEN;
  return TRUE;
}

##
# Closes an SCP session over SSH
# @returns TRUE on success, FALSE on failure
##
function ssh_scp_close()
{
  local_var ret;
  if(ssh_scp_state == SSH_SCP_CLOSED)
    return TRUE;

  if(ssh_scp_state != SSH_SCP_DONE)
    set_ssh_error(msg:"ssh_scp_close called under invalid state.");

  ret = ssh_close_channel();
  if (ret != 0)
  {
    set_ssh_error(msg:"Nessus failed to close SSH channel.");
    return FALSE;
  }
  ssh_scp_state = SSH_SCP_CLOSED;
  return TRUE;
}

##
# Pulls remote files using SCP over SSH
# @param location file(s) location
# @param recursive TRUE if recursive, FALSE if not
# @returns NULL on error or array with results
##
function ssh_scp_pull_file(location, recursive)
{
  local_var scp_command;

  if (location =~ INJECTION_PATTERN)
  {
    set_ssh_error(msg:"location path contains unsafe characters.");
    return NULL;
  }

  if(isnull(recursive)) recursive = FALSE;

  if(ssh_scp_state != SSH_SCP_CHANNEL_OPEN)
    set_ssh_error(msg:"ssh_scp_pull_file called under invalid state.");

  scp_command = "scp -f ";
  if(recursive) scp_command += "-r ";

  scp_command += location;

  if(!ssh_request_channel(s:"exec", extra:putstring(buffer:scp_command)))
    return NULL;

  return _ssh_scp_recv_files();
}

function _ssh_scp_recv_files ()
{
  local_var payload, tempbuf, item, cur_file, results, dir_path, dir_level, dir_path_history, tmp_len,
            directory, sub_path;
  payload = recv_ssh_packet();
  results = make_array();
  cur_file = NULL;
  dir_path = '';
  dir_path_history = make_list();
  dir_level = 0;

  while(ord(payload[0]) != SSH2_MSG_CHANNEL_CLOSE && ord(payload[0]) != 0 && strlen(payload) > 0)
  {
    if (ord(payload[0]) == SSH2_MSG_CHANNEL_WINDOW_ADJUST)
    {
      payload = ntol(buffer:payload, begin:5);
      r_window_size += payload;
    }
    else if (ord(payload[0]) == SSH2_MSG_CHANNEL_DATA || ord(payload[0]) == SSH2_MSG_CHANNEL_EXTENDED_DATA)
    {
      tempbuf = getstring(buffer:payload, pos:5);
      if(update_window_size(size:strlen(tempbuf)) != 0) break;
      if(!isnull(cur_file))
      {
        tmp_len = strlen(tempbuf);
        if((strlen(cur_file['contents']) + tmp_len) > cur_file['size'])
        {
          cur_file['contents'] += substr(tempbuf, 0, strlen(tempbuf) - 2);
          results[cur_file['path'] + '/' + cur_file['name']] = cur_file;
          cur_file = NULL;
        }
        else cur_file['contents'] += tempbuf;
      }
      else
      {
        if(tempbuf[0] == "C")
        {
          item = pregmatch(pattern:"^C(\d{4}) (\d+) ([^\n]+)\n$", string:tempbuf);
          if(isnull(item))
          {
            set_ssh_error(msg:"SCP protocol parse error.");
            return NULL;
          }
          cur_file = make_array(
            'name', item[3],
            'type', 'C',
            'size', int(item[2]),
            'perm', item[1],
            'contents', '',
            'rel_path', dir_path
          );
        }
        else if(tempbuf[0] == 'D')
        {
          item = pregmatch(pattern:"^D(\d{4}) (\d+) ([^\n]+)\n$", string:tempbuf);
          if(isnull(item))
          {
            set_ssh_error(msg:"SCP protocol parse error.");
            return NULL;
          }
 
          directory = make_array(
            'name', item[3],
            'type', 'D',
            'size', int(item[2]),
            'perm', item[1],
            'rel_path', dir_path
          );

          if(dir_path == '')
            dir_path = item[3];
          else
            dir_path += '/' + item[3];

          results[dir_path] = directory;

          dir_level++;
          dir_path_history = make_list(dir_path_history, item[3]);
        }
        else if(tempbuf[0] == 'E' && dir_level > 0)
        {
          sub_path = "/" + dir_path_history[dir_level - 1];
          dir_path -= sub_path;
          dir_level--;
        }
        else if(tempbuf[0] == '\x01')
        {
          set_ssh_error(msg:'SCP warning : ' + tempbuf);
          return NULL;
        }
        else if(tempbuf[0] == '\x02')
        {
          set_ssh_error(msg:'SCP error : ' + tempbuf);
          return NULL;
        }
        else
        {
          set_ssh_error(msg:'unhandled SCP message : ' + tempbuf);
          return NULL;
        }
      }
    }

    payload = raw_int32(i:remote_channel) + putstring(buffer:'\0');
    send_ssh_packet(payload:payload, code:raw_int8(i:SSH2_MSG_CHANNEL_DATA));

    payload = recv_ssh_packet();
  }
  return make_nested_list(results);
}


##
# Pushes remote file using SCP over SSH
# @param [location:string] file location
# @param [data:data] file contents
# @param [exec:bool] sets exec permissions on file if TRUE
# @param [close:bool] close the channel after push if TRUE. Default: TRUE
# @returns TRUE on success or FALSE on failure
##
function ssh_scp_push_file(location, data, exec, close)
{
  local_var scp_command;

  if (location =~ INJECTION_PATTERN)
  {
    set_ssh_error(msg:"location path contains unsafe characters.");
    return FALSE;
  }

  if(ssh_scp_state != SSH_SCP_CHANNEL_OPEN)
    set_ssh_error(msg:"ssh_scp_push_file called under invalid state.");

  scp_command = "scp -t ";

  scp_command += location;

  if(!ssh_request_channel(s:"exec", extra:putstring(buffer:scp_command)))
    return FALSE;

  return _ssh_scp_send_file(location:location, data:data, exec:exec, close:close);
}

##
# Pushes remote file using SCP over SSH
# @param [location:string] file location
# @param [data:data] file contents
# @param [exec:bool] sets exec permissions on file if TRUE
# @param [close:bool] close the channel after push if TRUE. Default: TRUE
# @returns TRUE on success or FALSE on failure
##
function _ssh_scp_send_file(location, data, exec, close)
{
  local_var status, offset, in_payload, out_payload, data_sz, filename,
            done, max_send, tempbuf;

  if(isnull(close)) close = TRUE;

  done = FALSE;


  filename = split(location, sep:'/', keep:FALSE);
  filename = filename[max_index(filename)-1];

  offset = uint(0);
  data_sz = uint(strlen(data));

  in_payload = recv_ssh_packet();

  if(update_remote_window_size(payload:in_payload))
    in_payload = recv_ssh_packet();

  status = getstring(buffer:in_payload, pos:5);

  if(int(status[0]) == SSH_SCP_SINK_WARNING)
  {
    set_ssh_error(msg:'SCP warning : '+status);
    return FALSE;
  }
  else if(int(status[0]) == SSH_SCP_SINK_ERROR)
  {
    set_ssh_error(msg:'SCP error : '+status);
    return FALSE;
  }
  else if(int(status[0]) != SSH_SCP_SINK_OK)
  {
    set_ssh_error(msg:'unhandled SCP message : '+status);
    return FALSE;
  }

  if(update_window_size(size:strlen(status)) != 0) return FALSE;

  // Send the command to tell the server what to expect
  if(exec)
    out_payload = raw_int32(i:remote_channel) + putstring(buffer:'C0774 '+strlen(data)+' '+filename+'\n');
  else
    out_payload = raw_int32(i:remote_channel) + putstring(buffer:'C0664 '+strlen(data)+' '+filename+'\n');
  send_ssh_packet(payload:out_payload, code:raw_int8(i:SSH2_MSG_CHANNEL_DATA));

  ssh_scp_state = SSH_SCP_WRITE_INIT;

  // Allow for the most data we can send, with some extra room for the
  // header and padding
  if(r_window_size < r_packet_size)
    max_send = r_window_size - 50;
  else
    max_send = r_packet_size - 50;


  if(max_send < 1)
  {
    set_ssh_error(msg:'No room to send data. Available space : '+max_send);
    return FALSE;
  }

  var sent_sum = 0;
  var adjust;
  var check_now = FALSE;

  // Start sending the data, occasionally checking for window adjustments
  while(offset < data_sz)
  {
    if(sent_sum >= max_send * 4 || check_now)
    {
      adjust = recv_ssh_packet();
      if(adjust != raw_int8(i:0) && !update_remote_window_size(payload:adjust))
      {

        if(ord(adjust[0]) == SSH2_MSG_CHANNEL_DATA)
        {
          status = getstring(buffer:in_payload, pos:5);

          if(int(status[0]) == SSH_SCP_SINK_WARNING)
          {
            set_ssh_error(msg:'SCP warning : '+status);
            return FALSE;
          }
          else if(int(status[0]) == SSH_SCP_SINK_ERROR)
          {
            set_ssh_error(msg:'SCP error : '+status);
            return FALSE;
          }
          else if(int(status[0]) != SSH_SCP_SINK_OK)
          {
            set_ssh_error(msg:'unhandled SCP message : '+status);
            return FALSE;
          }
        }
        else
        {
          set_ssh_error(msg:"received unexpected packet, type : "+sshlib::ssh2_packet_type_labels[ord(adjust[0])]);
          return FALSE;
        }
      }
      sent_sum = 0;
    }

    tempbuf = substr(data, offset, offset + max_send - 1 );
    offset += max_send;
    out_payload = raw_int32(i:remote_channel) + putstring(buffer:tempbuf);
    sent_sum += len(out_payload);
    send_ssh_packet(payload:out_payload, code:raw_int8(i:SSH2_MSG_CHANNEL_DATA));
    if(r_window_size < r_packet_size)
    {
      max_send = r_window_size - 50;
      check_now = TRUE;
    }
    else
    {
      max_send = r_packet_size - 50;
      check_now = FALSE;
    }
  }

  // Send null SSH string after data is complete.
  out_payload = raw_int32(i:remote_channel) + putstring(buffer:'\0');
  send_ssh_packet(payload:out_payload, code:raw_int8(i:SSH2_MSG_CHANNEL_DATA));

  ssh_scp_state = SSH_SCP_WRITE_DONE;

  in_payload = recv_ssh_packet();
  status = getstring(buffer:in_payload, pos:5);

  var ret = FALSE;
  switch ( int(status[0]) )
  {
    case SSH_SCP_SINK_OK:
      ssh_close_channel();
      ssh_scp_state = SSH_SCP_CLOSED;
      ret = TRUE;
      break;
    case SSH_SCP_SINK_WARNING:
      set_ssh_error(msg:'SCP warning : '+status);
      break;
    case SSH_SCP_SINK_ERROR:
      set_ssh_error(msg:'SCP error : '+status);
      break;
    default:
      set_ssh_error(msg:'unhandled SCP message : '+status);
      break;
  }


  return ret;
}
