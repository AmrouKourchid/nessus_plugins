#TRUSTED 891f3bd224d802f3e846c771fe9f9d430c29d1fab436feb20411fd385ed6ec0a65f955fa01762749e49b103fd2935ec542adce3f2c93594ee516704617d14568176eccfa6cc263826e485199a74b37843f6f3673afcbdd2de79ebd95351d963ec6e9994c383d60cdc3cd8cdbdbc518178d4dd70c557ec418bc0327dd97f9cb05ea98acfeb2f16458587ff2fd697b2ca51a908ca8ea4ff8e0ae3684c7eb1462b72f2bde6afa1d870111e0052b39430ce0763a2062ada57cf08a887c41aed53e82b709737e56646dc67e374bd713f41a2263528b0cfd969fbcdb0f2c12b6ca10594a843d153f32d1c51d0a8b6f54a5fa15eebbd3aabc0a4a17d96cb6e35b83c8bc6f1d3594c927c945e6d8b567aaa6603f6eb98f0fff81727dc2279ab356a0d812f90fd8fef6944d045686e0274957ee1548a1e122f240e9d4c2942b22fa3b8fb38362c3877ebe45051ce08daf980e9b4cfaf33cd3b26820ae9e84c0c169b1379fa0ca025a400716c2a4fea0c15b7f1a42e91c58a4f620ff23465bfe552a4211dd08ed40f8d3d6c32edbe01d38b72a8f081f668d373a19e01bd81f6cf44d9239fded98b53f64108dd660ef5dc791f60f42b254e5a4c59f81e3b6f6e4d0fe97a4f6e42c21a1109142176ebd5a5a9216d9be17b454cd506f8980156325571cada8a0d81bfd1bc5fc74fa21110cfb8fb576908d92f870f175d94b579f4897f2f37cec
#TRUST-RSA-SHA256 00dab9e0b78ffcf5a8c02bbbd318d6b3775299ada9f2767cef18818b91e4fa4ad05e5f4455ea89da027bb5ab2259fdcc9c8f120b926af073608621cdd38638cdf840be78a4fbf00817115457a84f32ca7b2c92fc9d4d90bc9d83ef30bf919a30aacf91c98cce492bbac43cd55a39b0255d9ff07b8fc8e73340adf290e1e236fa302c771b6aaf92eba0c1b67deeec1c5b14a92476ac09c4d328f966a956991b0713eaf0ff27095f7e90edeec9f45c5e2b28bada81c758543923abf9d6ff75f4ca4ee32dce7c660fb0dc91f74f5a29e6a70f56e214d5865d01719011b4e925ae673f22312d428d4141953d6a85ca7a892fbf37f694cd96b550273c9a76a6504cb1688773213784b95676cf190a4d07bd3f798631a348cb33ae9b6b3b16c048edf1f586f848570f32fd325eafd402333e2e5e05b46865393951b011a04044305afc07b0714f26878eff0ea9d388fa124266c53e265d426ad30d939306855cb7d3bd3b127d765a4277e56d746a22dcf0b8d7beb76fe73567aa3c1309ea8353584158e3757f20c1a427cbd5676cee8d1a2a9f637eb30a344a77de372da2b5df66969f613bad8b8e85eef6823d9fc8f796592e2dec9bd0988b9eb21c93d5229078c06b52ca1e9677795ed8d0fb251d8c6937e4ad69e22f3a71cbc60be94770fabaf8298b0dd8152bb9542ce9d033cce1457178d1d3ba1ee2ff474894102642eafeb672

include('compat_shared.inc');
include('ssh_globals.inc');
include('byte_func.inc');
include('ssh_compat.inc');
include('ssh_lib.inc');
include('ssh_func.inc');
include('debug.inc');

namespace netconf_ssh
{

  ##
  # Establishes connection with NETCONF server over SSH.
  ##
  function connect()
  {
    enable_ssh_wrappers();

    var port = sshlib::kb_ssh_transport();
    if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

    var success = ssh_open_connection();

    if (!success)
    {
      var error = get_ssh_error();
      var msg;
      if (strlen(error) == 0)
          msg = 'SSH authentication failed on port ' + port + ': unknown error.';
      else
          msg = 'SSH authentication failed on port ' + port + ': ' + error;
      exit(1, msg);
    }

    var ssh_protocol = get_kb_item('SSH/protocol');
    if (!isnull(ssh_protocol) && ssh_protocol == 1) exit(0, 'The SSH server listening on port '+port+' only supports version 1 of the SSH protocol.');

    var ret = ssh_open_channel();
    if (ret != 0)
    {
      ssh_close_connection();
      audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);
    }

    var channel = sshlib::_compat_session.get_default_channel();
    # SSH_MSG_CHANNEL_REQUEST
    var channel_req =
    raw_int32(i:channel.remote_channel) +
    putstring(buffer:'subsystem') +
    raw_int8(i:1) +  # want reply
    putstring(buffer:'netconf');
    send_ssh_packet(payload:channel_req, code:raw_int8(i:sshlib::PROTO_SSH2_MSG_CHANNEL_REQUEST));
    var res = recv_ssh_packet(timeout:5);

    # Check if target is running NETCONF based on the server hello
    var server_hello = recv();
    if (!pgrep(pattern:'<(?:nc:)?hello xmlns(?::nc)?="urn:ietf:params:xml:ns:netconf:base:1.0">', string:server_hello))
    {
      ssh_close_connection();
      audit(AUDIT_NOT_LISTEN, 'netconf', port);
    }
    set_kb_blob(name:'Host/netconf/capabilities', value:server_hello);
    set_kb_item(name:'Host/netconf', value:TRUE);
    set_kb_item(name:'Host/netconf/port', value:port);

    return server_hello;
  }

  ##
  # Sends a netconf payload over an already-established SSH channel,
  # wrapping it in a SSH_MSG_CHANNEL_DATA header
  ##
  function send()
  {
    var data = _FCT_ANON_ARGS[0];
    var channel = sshlib::_compat_session.get_default_channel();
    var payload =
      raw_int32(i:channel.remote_channel) + # global from ssh_func.inc
      putstring(buffer:data);

    dbg::detailed_log(lvl:1, msg:'Sending NETCONF packet over SSH',
                      msg_details:{'Data':{'lvl':3, 'value':payload}});
    send_ssh_packet(payload:payload, code:raw_int8(i:94));
  }

  ##
  # Receives a netconf payload, removing the SSH-related header
  # @return netconf payload
  ##
  function recv()
  {
    var netconf_data = '';
    var begin_time = unixtime();
    var timeout = 15;
    var ssh_res;
    # To get the full response we need to keep reading until we see ']]>]]>'.
    # This denotes the end of the response from the server.
    while (']]>]]>' >!< netconf_data && (unixtime() - begin_time) < timeout)
    {
      ssh_res = recv_ssh_packet(timeout:5);
      netconf_data = netconf_data + '\n' + substr(ssh_res, 9); # code, channel, and length ignored
    }

    dbg::detailed_log(lvl:1, msg:'Received NETCONF packet over SSH',
                      msg_details:{'Data':{'lvl':3, 'value':netconf_data}});

    return netconf_data;
  }

  ##
  # Closes the SSH connection.
  ##
  function disconnect()
  {
    ssh_close_connection();
  }

}
