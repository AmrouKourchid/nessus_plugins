#TRUSTED a8f073e96d657fcbc77f0ad97b1ec041b8af63d98c4ef2c0f5211b9ab3d62969906369407d8b8bc9b877af7c55fc0466354dda4da439a3f8c792d033a2d7bb3eda0c46abfd5160a757b5fdb0d4eb50e2eb391e195b657f1d7b20be8ccedc823c9a02e350544b5eec9c371967337e0d89bfdc5c58539d2660ea74219742fcd806df6149174a4e0c6e794bae99a9990e41bcc53a19f341b0e538530327f7fb5108103023a23ab1facf1a686cab365844b3e548d3c52790b225c6c5c69dfce875510b08cfb772e737a664deb36fcd48260b5462b942f7205269bfa4ad26ddddc38200e843d8f4e760d94a2df57ef80aa36c0f28b7463d18d307ef63a154b4bab298ba06f01c58251b5151e677b4386701d9ea0632539e382192590dff6b492946b2945968816bb271974550f30e2116c1c3963c5ef9635140d43a1de63a570b9fb19c89d3c54de4ebc5827aed90be4fcf23747a9b77bbcf5cea9a2c6bdc4642f53837ec16571c86b0a9def1939d466e757a1fa7ade37f17864928f9fef859b811bad9772299b1979e553f561f0ca50f9bec792fd06e60917e3f1852cebb6115a534cb3b05deb86550eee3b8e10feaadb40a97d84813274ff9613ed60d1635e5a60d342d5b2e4ccb6efe06daaa6b9be826639b5aa89904a29e1c7501d36b6302e064f8f34f3f60ee4457922f67ccbbdb014b25d8939bfaceeff963b1f9432fc419c3
#TRUST-RSA-SHA256 43b6209e4b286182efaf0cac9ec98f3a2774c5e255038c7e335d4f65566a5d4e351c6cefb86ed98b2435087824ff8550de6eec0be587efbfd30a2914cbe6cb0de12f73b53efcaa560dbbf450d938f7c480f567ce09148813abcaaba304471a187e78f4e691fa35e9de76183115cb48243938c2dc76d74e8191b8116f4920f683ace7359c5feb80893c52a13f69f4804ad0a39834706163852fd957a07796e73bc366d1263fc98cc21667d9b96a707b385d245a494b95085856295e2e5d86c638742f367e2639ec0a54b09fc1e938b0f4a3253d6acc279d9817714ea0e49f308dca8fd2171557c49fc8bdd5b196b5c2a340d2b19b98f2bb812e9e43cb7b15184eea83066b78a4cd8df1a4a03c5a78470c54f03e94d2b2137016e972989664991d709c8d9ba0ed317428897ee1d6d65af06ae98e6732ec001c2ef7b611b2c8798acec871db56f6f986abcdd0d612579d55d3ec16a13b5b2383b647c63e8e673113c8f9b0d522cf3cec7f8c67f748da28ac8046c0269f143a6c2e0c0ec383e18a3c0116d236fde4572c98cc4f7948e1ad4e74e7f3be2a7ee66ef826944170c8447f5b6e3d8613a1fdd51d8bc0660d5e3cb4ceba22663c719b16fda9a6adcb3224c1ca6bac2c0c671579ebd76e2f30c6e157fd4eb390c89a6841fe804e711346ee5ba25fd33ee9007fa34d7958fcd132eb472556f6bfa40e16c3743202188d927a49
#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.13
#

include("byte_func.inc");
include("ssh_globals.inc");
include("ssh_func.inc");
include("crc_func.inc");
include("crypto_func.inc");

global_var _ssh1_encryption, _ssh1_key, _ssh1_session_id;
global_var _tripledes_dec_iv, _tripledes_enc_iv, _tripledes_key;
global_var cipher_type;

global_var SSH_CIPHER_BLOWFISH = 6;
global_var SSH_CIPHER_3DES = 3;

function tripledes_initialize(key)
{
 local_var i;

 _tripledes_key = _tripledes_enc_iv = _tripledes_key = make_list();
 for ( i = 0 ; i < 3 ; i ++ )
 {
  _tripledes_dec_iv[i] =  _tripledes_enc_iv[i] = crap(data:'\0', length:8);
 }

 _tripledes_key[0] = substr(key, 0, 7);
 _tripledes_key[1] = substr(key, 8, 15);
 _tripledes_key[2] = substr(key, 16, 23);
}


function tripledes_encrypt(data)
{
 data = des_cbc_encrypt2(data:data, key:_tripledes_key[0], iv:_tripledes_enc_iv[0]);
 _tripledes_enc_iv[0] = data[1];

 data = des_cbc_decrypt2(data:data[0], key:_tripledes_key[1], iv:_tripledes_enc_iv[1]);
 _tripledes_enc_iv[1] = data[1];

 data = des_cbc_encrypt2(data:data[0], key:_tripledes_key[2], iv:_tripledes_enc_iv[2]);
 _tripledes_enc_iv[2] = data[1];

 data = data[0];
 return data;
}

function tripledes_decrypt(data)
{
 local_var p;

 data = des_cbc_decrypt2(data:data, key:_tripledes_key[2], iv:_tripledes_dec_iv[2]);
 _tripledes_dec_iv[2] = data[1];

 data = des_cbc_encrypt2(data:data[0], key:_tripledes_key[1], iv:_tripledes_dec_iv[1]);
 _tripledes_dec_iv[1] = data[1];

 data = des_cbc_decrypt2(data:data[0], key:_tripledes_key[0], iv:_tripledes_dec_iv[0]);
 _tripledes_dec_iv[0] = data[1];

 data = data[0];

 return data;
}


function des_cbc_encrypt2(data, key, iv)
{
 local_var l, len, j, tmp, to_encrypt;

 len = strlen(data);
 tmp = NULL;

 for(l=0; l<len; l+=8)
 {
  to_encrypt = substr(data, l, l+7);

  for (j=0; j<8; j++)
    to_encrypt[j] = raw_string(ord(to_encrypt[j]) ^ ord(iv[j]));

  iv = DES (in:to_encrypt, key:set_des_key(key:key), _string:FALSE, type:1);

  tmp += iv;
 }

 return make_list(tmp, iv);
}


function des_cbc_decrypt2(data, key, iv)
{
 local_var l, len, j, tmp, dec, to_decrypt;

 len = strlen(data);
 tmp = NULL;

 for(l=0; l<len; l+=8)
 {
  to_decrypt = substr(data, l, l+7);

  dec = DES (in:to_decrypt, key:set_des_key(key:key), _string:FALSE, type:0);
  for (j=0; j<8; j++)
    dec[j] = raw_string(ord(dec[j]) ^ ord(iv[j]));

  iv = to_decrypt;

  tmp += dec;
 }

 return make_list(tmp, iv);
}


function ssh1_recv(timeout)
{
 local_var header, len, payload, plen, padding, crc, data, null_pkt;

 null_pkt = raw_int8(i:0);

 header = recv(socket:_ssh_socket, length:4, min:4, timeout:timeout);
 if (strlen(header) < 4) return null_pkt;

 len = ntol (buffer:header, begin:0);
 if ((len == 0) || (len > max_packet_size)) return null_pkt;

 plen = 8 - ((len)%8);

 padding = recv(socket:_ssh_socket, length:plen, min:plen, timeout:timeout);
 if(strlen(padding) < plen ) return null_pkt;

 payload = recv(socket:_ssh_socket, length:len, min:len, timeout:timeout);
 if (strlen(payload) < len) return null_pkt;

 if (_ssh1_encryption)
 {
  data = padding+payload;

  if ( cipher_type == SSH_CIPHER_BLOWFISH )
   payload = blowfish_decrypt(data:data);
  else if ( cipher_type == SSH_CIPHER_3DES )
   payload = tripledes_decrypt(data:data);
  padding = substr(payload, 0, plen-1);
  payload = substr(payload, plen, strlen(payload)-1);
 }

 len = strlen(payload);
 crc = ntol(buffer:payload, begin:len-4);
 payload = substr(payload, 0, len-5);

 if (crc != crc32(data:padding+payload))
   return null_pkt;

 # SSH_MSG_DEBUG
 if (ord(payload[0]) == 36)
   return ssh1_recv(timeout:timeout);

 return payload;
}


function ssh1_send(payload, code)
{
 local_var crc, data, len, plen;

 data = raw_int8(i:code) + payload;

 len = strlen(data) + 4;
 plen = 8 - ((len)%8);

 data = crap(data:'\0', length:plen) + data;
 data = data + raw_int32(i:crc32(data:data));

 if (_ssh1_encryption)
 {
   if ( cipher_type == SSH_CIPHER_BLOWFISH )
    data = blowfish_encrypt(data:data);
   else if ( cipher_type == SSH_CIPHER_3DES )
    data = tripledes_encrypt(data:data);
 }

 data = raw_int32(i:len) + data;

 send(socket:_ssh_socket, data:data);
}


function raw_int16(i)
{
 local_var buf;

 buf = raw_string (
        (i>>8) & 255,
        (i) & 255
		 );
 return buf;
}


function ntos(buffer,pos)
{
 local_var len;

 len = ord(buffer[pos])*256 +
       ord(buffer[pos+1]);

 return len;
}


function get_bignum1(buffer, pos)
{
 local_var len, bits;

 bits = ntos(buffer:buffer, pos:pos);
 len = (bits + 7) / 8;

 return substr(buffer, pos+2, pos+2+len-1);
}


function putbignum1(buffer)
{
 local_var len;

 len = strlen(buffer) * 8;
 return raw_int16(i:len) + buffer;
}


function len_long()
{
 return 4;
}


function len_bn(bn)
{
 return 2 + strlen(bn);
}


global_var RSA1_KEY_ID = 'SSH PRIVATE KEY FILE FORMAT 1.1\n\0';

function parse_private_key(data, passphrase)
{
 local_var len, key, pos, e, n, d, comment;
 local_var id_len, cipher, reserved, klen;
 local_var id, bits;

 pos = 0;
 len = strlen(data);
 id_len = strlen(RSA1_KEY_ID);

 if ( len < (id_len+9))
   return NULL;

 id = substr(data, 0, id_len-1);
 if (id >!< RSA1_KEY_ID)
   return NULL;

 cipher = ord(data[id_len]);
 if (cipher != 0 && cipher != 3)
 {
   set_ssh_error(msg:strcat("Unsupported cipher in private key: ", cipher));
   return NULL;
 }

 reserved = ntol(buffer:data, begin:id_len+1);
 klen = ntol(buffer:data, begin:id_len+5);

 pos = id_len + 9;

 # parse n
 n = get_bignum1(buffer:data, pos:pos);
 pos += strlen(n) + 2;

 # parse e
 e = get_bignum1(buffer:data, pos:pos);
 pos += strlen(e) + 2;

 comment = getstring(buffer:data, pos:pos);
 pos += 4 + strlen(comment);

 data = substr(data, pos, len-1);

 # 3des
 if (cipher == 3)
 {
  passphrase = MD5(passphrase);
  passphrase = passphrase + substr(passphrase, 0, 7);

  data = des_cbc_decrypt2(data:data, key:substr(passphrase, 0, 7), iv:'\0\0\0\0\0\0\0\0');
  data = des_cbc_encrypt2(data:data[0], key:substr(passphrase, 8, 15), iv:'\0\0\0\0\0\0\0\0');
  data = des_cbc_decrypt2(data:data[0], key:substr(passphrase, 16, 23), iv:'\0\0\0\0\0\0\0\0');
  data = data[0];
 }

 if (ntos(buffer:data, pos:0) != ntos(buffer:data, pos:2))
   return NULL;

 d = get_bignum1(buffer:data, pos:4);

 return make_list(e,n,d);
}



function ssh_kex1(nofingerprint)
{
 local_var payload, cookie, pos;
 local_var skey_bits, skey_e, skey_n;
 local_var hkey_bits, hkey_e, hkey_n;
 local_var cflags, ciphers, auth;
 local_var sflags, i, id;
 local_var session, enc, cipher;
 local_var fkey, fe, fn;

 _ssh1_encryption = FALSE;

 payload = ssh1_recv();
 if (ord(payload[0]) != 2)
 {
   set_ssh_error(msg:strcat("Received code was not SSH_SMSG_PUBLIC_KEY (2). It was : ", ord(payload[0])));
   return -1;
 }

 cookie = substr(payload,1,8);

 pos = 9;

 # server key
 skey_bits = ntol(buffer:payload, begin:pos);
 pos += len_long();
 skey_e = get_bignum1(buffer:payload, pos:pos);
 pos += len_bn(bn:skey_e);
 skey_n = get_bignum1(buffer:payload, pos:pos);
 pos += len_bn(bn:skey_n);

 # host key
 hkey_bits = ntol(buffer:payload, begin:pos);
 pos += len_long();
 hkey_e = get_bignum1(buffer:payload, pos:pos);
 pos += len_bn(bn:hkey_e);
 hkey_n = get_bignum1(buffer:payload, pos:pos);
 pos += len_bn(bn:hkey_n);

 if (isnull(nofingerprint) || nofingerprint == FALSE)
 {
  fkey = get_kb_item("SSH/KnownFingerprint/ssh-rsa1");
  if (fkey)
  {
   fkey = split(fkey, sep:'|', keep:FALSE);
   fe = bn_raw2dec(hkey_e);
   fn = bn_raw2dec(hkey_n);
   if (fe != fkey[0] || fn != fkey[1])
   {
    set_ssh_error(msg:"Server public key does not match the known host fingerprint");
    return -1;
   }
  }
 }

 sflags = ntol(buffer:payload, begin:pos);
 pos += len_long();
 ciphers = ntol(buffer:payload, begin:pos);
 pos += len_long();
 auth = ntol(buffer:payload, begin:pos);

 # detect blowfish or 3des
 if (ciphers & ( 1 << 6 ) )
 {
   cipher_type = SSH_CIPHER_BLOWFISH;
 }
 else if ( ciphers & ( 1 << 3 ) )
 {
   cipher_type = SSH_CIPHER_3DES;
 }
 else
 {
   set_ssh_error(msg:strcat("The remote SSH server does not support blowfish nor 3des encryption."));
   return -1;
 }

 id = MD5(hkey_n + skey_n + cookie);
 _ssh1_session_id = id;

 session = bn_random(need:(32*8));
 if (strlen(session) > 32)
   session = substr(session, 0, 31);

 _ssh1_key = session;
 if ( cipher_type == SSH_CIPHER_BLOWFISH )
  blowfish_initialize (key:_ssh1_key);
 else if ( cipher_type == SSH_CIPHER_3DES )
  tripledes_initialize(key:_ssh1_key);

 for (i=0; i<16; i++)
   session[i] = raw_string(ord(session[i]) ^ ord(id[i]));

 if (bn_cmp(key1:skey_n, key2:hkey_n) <= 0)
 {
  enc = rsa_public_encrypt(data:session, e:skey_e, n:skey_n);
  enc = rsa_public_encrypt(data:enc, e:hkey_e, n:hkey_n);
 }
 else
 {
  enc = rsa_public_encrypt(data:session, e:hkey_e, n:hkey_n);
  enc = rsa_public_encrypt(data:enc, e:skey_e, n:skey_n);
 }

 cipher = cipher_type;
 cflags = 0;

 payload = raw_int8(i:cipher) + cookie + putbignum1(buffer:enc) + raw_int32(i:cflags);

 ssh1_send(payload:payload, code:3);

 _ssh1_encryption = TRUE;

 payload = ssh1_recv();
 if (ord(payload[0]) != 14)
 {
   set_ssh_error(msg:strcat("Received code was not SSH_SMSG_SUCCESS (14). It was : ", ord(payload[0])));
   return -1;
 }

 return 0;
}



function ssh_userauth1(login, password, priv, passphrase)
{
 local_var payload, rsa, challenge, dec, hash;

 payload = putstring(buffer:login);

 # SSH_CMSG_USER
 ssh1_send( payload:payload, code:4);

 payload = ssh1_recv();
 if (ord(payload[0]) != 15)
 {
   set_ssh_error(msg:strcat("Received code was not SSH_SMSG_FAILURE (15). It was : ", ord(payload[0])));
   return -1;
 }

 if (!isnull(priv))
 {
  rsa = parse_private_key(data:priv, passphrase:passphrase);
  if (isnull(rsa))
  {
   set_ssh_error(msg:"Invalid RSA1 private key!");
   return -1;
  }

  payload = putbignum1(buffer:rsa[1]);

  # SSH_CMSG_AUTH_RSA
  ssh1_send(payload:payload, code:6);

  payload = ssh1_recv();
  if (ord(payload[0]) != 7)
  {
   set_ssh_error(msg:strcat("Received code was not SSH_SMSG_AUTH_RSA_CHALLENGE (7). It was : ", ord(payload[0])));
   return -1;
  }

  challenge = get_bignum1(buffer:payload, pos:1);
  dec = rsa_private_decrypt(e:rsa[0], n:rsa[1], d:rsa[2], sig:challenge);
  hash = MD5(dec + _ssh1_session_id);

  payload = hash;

  # SSH_CMSG_AUTH_RSA_RESPONSE
  ssh1_send(payload:payload, code:8);

  payload = ssh1_recv();
  if (ord(payload[0]) != 14)
  {
   set_ssh_error(msg:strcat("Received code was not SSH_SMSG_SUCCESS (14). It was : ", ord(payload[0])));
   return -1;
  }
 }
 else
 {
  payload = putstring(buffer:password);

  # SSH_CMSG_AUTH_PASSWORD
  ssh1_send(payload:payload, code:9);

  payload = ssh1_recv();
  if (ord(payload[0]) != 14)
  {
   set_ssh_error(msg:strcat("Received code was not SSH_SMSG_SUCCESS (14). It was : ", ord(payload[0])));
   return -1;
  }
 }

 return 0;
}


function ssh_cmd1(cmd, timeout, su, supass, dbegin, dend, derror, sent_dbegin, noexec, cisco, enable_pass)
{
 local_var payload, ret, code, spass, tempbuf, ltempbuf, does_echo, last, last5;
 local_var cmdd, sub1, sub2, su_sudo_pass;
 local_var iter, line, cmd_prompt, pagination_prompt, used_exec, val;

 if (_ssh_ltype == 1)
 {
  ssh_close_connection();
  ret = ssh_open_connection();
  if (ret <= 0)
  {
   set_ssh_error(msg:"SSH_CMD1: can not open a new socket");
   return NULL;
  }
 }

 does_echo = 0;

 used_exec = 0;
 if (!cisco && !noexec && (isnull(su) || su == SU_NONE))
 {
  payload = putstring(buffer:cmd);

  # SSH_CMSG_EXEC_CMD
  ssh1_send(payload:payload, code:13);

  used_exec = 1;
 }
 else
 {
  payload = putstring(buffer:"vt100") + raw_int32(i:80) + raw_int32(i:24) + raw_int32(i:640) + raw_int32(i:480) +
            raw_int8(i:193) + raw_int32(i:33000) +
	    raw_int8(i:192) + raw_int32(i:33000) +
	    raw_int8(i:0);

  # SSH_CMSG_REQUEST_PTY
  ssh1_send(payload:payload, code:10);

  payload = ssh1_recv();
  if (ord(payload[0]) != 14)
  {
   set_ssh_error(msg:strcat("Received code was not SSH_SMSG_SUCCESS (14). It was : ", ord(payload[0])));
   return NULL;
  }

  # SSH_CMSG_EXEC_SHELL
  ssh1_send(payload:NULL, code:12);

  spass = 0;
  su_sudo_pass = 0;
 }

 payload = ssh1_recv(timeout:timeout);
 code = ord(payload[0]);

 ret = NULL;

 # SSH_SMSG_STDOUT_DATA && SSH_SMSG_STDERR_DATA
 iter = 0;
 while (code == 17 || code == 18)
 {
  tempbuf = NULL;

  # nb: arbitrary limit to avoid an infinite loop.
  if (strlen(ret) == 0 && ++iter > 100) break;

  if (
    code == 17 ||
    # nb: at least for Red Hat 4 and Solaris, normal command output is
    #     returned as stderr when using exec.
    (code == 18 && used_exec)
  )
  {
   tempbuf = getstring (buffer:payload, pos:1);
   # Strip out escape sequences that might obscure the prompt; eg,
   #   0x00:  1B 5B 30 31 3B 33 32 6D 6E 65 73 73 75 73 40 65    .[01;32mnessus@e
   #   0x10:  78 61 6D 70 6C 65 2E 63 6F 6D 1B 5B 30 31 3B 33    xample.com.[01;3
   #   0x20:  34 6D 20 7E 20 24 1B 5B 30 30 6D 20                4m ~ $.[00m
   tempbuf = ereg_replace(pattern:'\x1b\\[[0-9]+(;[0-9]+)?[A-Za-z]', replace:'', string:tempbuf);
   tempbuf = ereg_replace(pattern:'\x1b\\[\\?[0-9]+[A-Za-z]', replace:'', string:tempbuf);
   tempbuf = ereg_replace(pattern:'\x1b[0-9]*E', replace:'\n', string:tempbuf);

   if (!used_exec && strlen(ret) == 0)
   {
     # nb: Red Hat 4 echoes back a modified version of the command that
     #     otherwise would not be removed from the command output.
     tempbuf = ereg_replace(pattern:'^([^\r\n]+) \r', replace:"\1", string:tempbuf);
   }

   ret += tempbuf;

   if ( sent_dbegin >< ret ) does_echo = 1;

  if (cisco)
  {
    if (strlen(tempbuf) > 0) last = tempbuf[strlen(tempbuf) - 1];
    else last = NULL;
    if (last == " " && strlen(tempbuf) > 1) last = tempbuf[strlen(tempbuf) - 2];

    if (
      spass == 0 &&
      (
        last == "#" ||
        (last == ">" && strlen(enable_pass) == 0)
      )
    ) spass = 2;

    if (spass == 0 && last == ">" && strlen(enable_pass) > 0)
    {
      payload = putstring(buffer:'enable\n');
      # SSH_MSG_STDIN_DATA
      ssh1_send(payload:payload, code:16);
      spass = 1;
    }
    else if (
      spass == 2 &&
      (
        last == "#" ||
        (last == ">" && strlen(enable_pass) == 0)
      )
    )
    {
      payload = putstring(buffer:cmd);
      # SSH_MSG_STDIN_DATA
      ssh1_send(payload:payload, code:16);

      timeout += 15;
      spass = 4;

      tempbuf = "";
    }
    else if (
      spass > 0 && spass <= 3 &&
      strlen(enable_pass) && is_password_prompt(tempbuf)
    )
    {
      if (spass >= 3)
      {
        _ssh_cmd_error = 'The provided Cisco \'enable\' password does not appear to be correct.';
        return NULL;
      }

      payload = putstring(buffer:enable_pass+'\n');
      # SSH_MSG_STDIN_DATA
      ssh1_send(payload:payload, code:16);

      spass++;
    }
    else if (spass == 4)
    {
      ltempbuf = tolower(tempbuf);
      if ( "--more--" >< ltempbuf || "<--- more --->" >< ltempbuf  )
      {
        ssh1_send(payload:putstring(buffer:' '), code:16);
      }
      else if (last == '#' || last == '>') break;
    }
  }
  else
  {
    if ( strlen(tempbuf) > 5 ) last5 = substr(tempbuf, strlen(tempbuf) - 6, strlen(tempbuf) - 1 );
    else last5 = tempbuf;

    if (spass == 0 && "Press any key to continue" >< tempbuf)
    {
      replace_kb_item(name:"/tmp/ssh_cmd/initial_page", value:tempbuf);

      ssh1_send(payload:putstring(buffer:' '), code:16);

      ret = tempbuf = "";
    }
    else if (spass == 0 && ("$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5))
    {
      if (isnull(su))
      {
        foreach line (split(tempbuf))
        {
          # empty
        }
        cmd_prompt = line;
        replace_kb_item(name:"/tmp/ssh_cmd/cmd_prompt", value:cmd_prompt);

        payload = putstring(buffer:cmd+'\n');
        # SSH_MSG_STDIN_DATA
        ssh1_send(payload:payload, code:16);

        spass = 4;

        ret = tempbuf = "";
      }
      else
      {
        for ( sub1 = 0 ; sub1 < strlen(cmd) ; sub1 += 1024 )
        {
          if ( strlen(cmd) <= sub1 + 1023 ) sub2 = strlen(cmd) - 1;
          else sub2 = sub1 + 1023;
          cmdd = substr(cmd, sub1, sub2);
          payload = putstring(buffer:cmdd);
          # SSH_MSG_STDIN_DATA
          ssh1_send(payload:payload, code:16);
        }
        spass = 1;
      }
    }
    else if (isnull(su) && spass == 4)
    {
      ltempbuf = tolower(tempbuf);
      if ("-- more --" >< ltempbuf || "next page: space" >< ltempbuf)
      {
        foreach line (split(tempbuf))
        {
          # empty
        }
        pagination_prompt = line;
        ssh1_send(payload:putstring(buffer:' '), code:16);
      }
      else if ("$" >< last5 || "#" >< last5 || ">" >< last5 || "%" >< last5) break;
    }

    # End of su/sudo command
    if (!isnull(su) && (dend >< tempbuf || derror >< tempbuf))
    {
     if ( su == SU_SU && spass < 2)
       ret = NULL;
     else
       break;
    }

    # su/sudo: set password if needed
    if ( "password:" >< tolower(tempbuf) && strlen(tempbuf) > 0 && tempbuf[strlen(tempbuf) - 1] != '\n' )
     {
      if (  su == SU_SU_AND_SUDO && spass == 1 && su_sudo_pass < 2 )
      {
       payload = putstring(buffer:strcat(supass, '\n'));
       ssh1_send(payload:payload, code:16);
       su_sudo_pass ++;
       if ( su_sudo_pass == 2 ) spass = 2;
       }
       else if ( ! isnull(supass) && spass == 1 )
       {
        payload = putstring(buffer:strcat(supass, '\n'));
        ssh1_send(payload:payload, code:16);
        spass = 2;
       }
       else if ( isnull(supass) || spass >= 2 ) # Password failed
       {
        ssh_close_channel(end:0);
        return NULL;
       }
     }
    }

    payload = ssh1_recv(timeout:timeout);
    code = ord(payload[0]);
  }
 }

 if (cisco && strlen(ret))
 {
   # remove the command, which Cisco echoes back along with a CR/NL.
   ret = substr(ret, strlen(cmd)+2);

   # remove the final prompt.
   ret = ereg_replace(pattern:'[\r\n]+[^\r\n]+[>#] *$', replace:"", string:ret);

   # remove pagination.
   ret = ereg_replace(pattern:'\r\n (--More--|<--- More --->) \x08+ +\x08+', replace:'\r\n', string:ret);
   ret = str_replace(find:'\x1b\x5b7m--More--\x1b\x5bm\x0d\x21\x1b\x5b\x4b\n', replace:'\r\n', string:ret);
 }

 if (isnull(su))
 {
   if (ret)
   {
     # nb: from an HP ProCurve switch when running a command
     #     directly rather than through a shell.
     if (
       stridx(ret, "SSH command execution is not supported.") == 0 ||
       stridx(ret, "% Unrecognized command found at '^' position") >= 0
     )
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       return NULL;
     }
     # nb: from a Juniper router running Junos.
     else if (stridx(ret, "error: syntax error, expecting <command>: -c") >= 0)
     {
       _ssh_cmd_error = strcat(_ssh_cmd_error, chomp(ret));
       return NULL;
     }
     else if (noexec)
     {
       if (stridx(ret, cmd+'\n') == 0) ret = ret - (cmd+'\n');
       else if (stridx(ret, cmd+' \n') == 0) ret = ret - (cmd+' \n');
       else if (stridx(ret, cmd+'\r\n') == 0) ret = ret - (cmd+'\r\n');
       else if (stridx(ret, cmd+' \r\n') == 0) ret = ret - (cmd+' \r\n');
       if (cmd_prompt && cmd_prompt >< ret)
       {
         val = stridx(ret, cmd_prompt);
         if (val == strlen(ret) - strlen(cmd_prompt)) ret = substr(ret, 0, val-1);
       }
       if (pagination_prompt && pagination_prompt >< ret)
       {
         tempbuf = "";
         foreach line (split(ret))
         {
           if (stridx(line, pagination_prompt) != 0) tempbuf += line;
         }
         ret = tempbuf;
       }
       ret = chomp(ret);
     }
   }
 }

 if (!isnull(su))
 {
  if (derror >< ret)
  {
    # Try to capture the error message.
    foreach line (split(ret, keep:TRUE))
    {
      if (
        (
          (su == SU_SUDO || su == SU_SU_AND_SUDO) &&
          "is not in the sudoers file" >< line
        ) ||
        (
          (su == SU_SU || su == SU_SU_AND_SUDO) &&
          "su: Authentication failure" >< line
        ) ||
        (
          (su == SU_SUDO || su == SU_SU_AND_SUDO || su == SU_DZDO) &&
          (
            "Sorry, user" >< line ||
            "sorry, you are not allowed to set" >< line
          )
        )
      )
      {
        if (su == SU_DZDO)
        {
          if ("Sorry, user" >< line) line = strstr(line, "Sorry, user");
          if ("sorry, you are not allowed to set" >< line) line = strstr(line, "sorry, you are not allowed to set");
        }
        _ssh_cmd_error = strcat(_ssh_cmd_error, line);
      }
    }
    if (_ssh_cmd_error) _ssh_cmd_error = chomp(_ssh_cmd_error);

    return NULL;
  }
  if (dbegin >!< ret || dend >!< ret) return NULL;
  if (dbegin >< ret)
    ret = substr(strstr(ret, dbegin), strlen(dbegin), strlen(ret)-1);
  if (dend >< ret)
  {
   # sun ssh echoes output even if the option is disabled
   if (does_echo)
    {
     ret = substr(ret, 2, stridx(ret, dend)-1);
    }

   else
     ret = substr(ret, 1, stridx(ret, dend)-1);
  }
 }


 return ret;
}

