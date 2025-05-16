#TRUSTED 0204a2df2f334641c0ac2d82d0c2638ac282112c225f049bf7586ac999af06f2c9780872d12f87e7d93e877c513932aa7fa8fbe0d85f035b701b14f04fd5d4359c9f9bb79826d6d80520ca0eba371499cc58071b4bd44c2b8175b083b9722af95670e8922b8b6ebccb838bc45e2e6c47765581cf17aa6df92f102852c8aef133e29c5f55c894d681dbdea55334a8e46bb8a258cfd9b6c031478f32788481970895daee4be2439b5c50a89677ad1e55904d69c59adfe7da7059e4bb8ac2970a36affe19ced42a6330ae87c414b8c9c24e4f89aae0a165c719f90711aa03b15f039da447e1be0557b20c6d39deed81d39e71b3f919061e948c8d802cd5294072801b04f8b42cd0765b3a43a856e875fcd970197bd5c660bc7521fa9734fe523aaf116027b374576e3d2a2f541559ea9cfc00504112157d80ec2245ca2c6bcacc6af1c534bd5a896dabda035c690d14c2b0c88ecaf0a8001c0ac85ccf687f3b1d79c871ff3ca368bf2044d768f1905b3ffea4176996d263777439462608c0cbf53b181c83fa10683e52aa90e71356b9e1f2a478f9a1d4df0c28a3dd3e7c00db1588bd4fa3596818da306f212bc69929cf073f98d45dcba8d99b6b40aa2580339faa7415a565eb5c9a4db3742b957995ef097aff5c6b1984c00733bfad25408249214f69d36044db859c8cb39839eb689e5acbd8e94cc8ef8cc5815165a1cf5d49bd
#TRUST-RSA-SHA256 0b2e3ee75d9c27a57c4a508c41d1039f26a8a28cadc39275d22359ec495131e72723003f53f938764b7a30839462d6bef3983c7758c14e7331bf7df37abe00b28f6dd2d6c00d171d1af45baf77fc6962388494d9b08183504f28ab8d7c07f77a3588a2ebfc077528a7ed448958a35b62deadcce62c1040828749582559fd6c0d515b2803091f00b0aa8ccf5b4eb478d7ce9a29e57c70f8cfe5b3e953cad64c727e71cad113f049da932c10c4ad70b6a5a19ced31f25b20f4c6b2b33f3bcaba07ca6bfe57d199e0e6910766e405586a98eb127f5318cf2ed479cb42ffe53ae2d1160854f1df1032ddc4403a73dbf7b966b05c8a0c4d0d15287f5d479e8c727610318799569c43562a1eb4611938a1ad3847e5e76620f5a3e559dcb0b889865f872650fe3bd28e83a0565b8b49cf26c1d148047c63bbc3b1788446bbb47534b9d2a6cc73152799a4ff73723f13d6047ab6fb239b3914f01abb33127f1630608964d0728b5aa7aa0519fba05cfb7d11ae3dbf1f308406c4a343042e2cba7f4f18961f2c178c5416e56e31c771c102bbd89547707275afd9d08e56c4574ef45c9dd967038486d1557508c34e9ef1291d004f201903b5a3015b4d61f1f00d0b1aeb7ca3e9aa368aee9671568547e7ebea528096d2a3d3dde768e315a6b1a80932fef7f3beac15bab8b2670f1decee3e836143db5d9d9944e5dee21bfa47ef047639e0

#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

global_var MAX_ADDITIONAL_SMB_LOGINS;
MAX_ADDITIONAL_SMB_LOGINS = 3;

if (description)
{
 script_id(10870);
 script_version("1.109");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

 script_name(english:"Login configurations");
 script_summary(english:"Logins for HTTP, FTP, NNTP, POP2, POP3, IMAP, IPMI, and SMB.");

 script_set_attribute(attribute:"synopsis", value:
"Miscellaneous credentials.");
 script_set_attribute(attribute:"description", value:
"This plugin provides the username and password credentials for common
servers, such as HTTP, FTP, NNTP, POP2, POP3, IMAP, IPMI, and SMB
(NetBios).

Some plugins will use those credentials when needed. If you do not
provide the credentials, those plugins will not be able to run.

Note that this plugin does not do any security checks.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/04");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_family(english:"Settings");

 script_dependencies("datapower_settings.nasl");

 script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_add_preference(name:"HTTP account :", type:"entry", value:"");
 script_add_preference(name:"HTTP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"NNTP account :", type:"entry", value:"");
 script_add_preference(name:"NNTP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"FTP account :", type:"entry", value:"anonymous");
 script_add_preference(name:"FTP password (sent in clear) :", type:"password", value:"nessus@nessus.org");
 script_add_preference(name:"FTP writeable directory :", type:"entry", value: "/incoming");

 script_add_preference(name:"POP2 account :", type:"entry", value:"");
 script_add_preference(name:"POP2 password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"POP3 account :", type:"entry", value:"");
 script_add_preference(name:"POP3 password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"IMAP account :", type:"entry", value:"");
 script_add_preference(name:"IMAP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"IPMI account :", type:"entry", value:"");
 script_add_preference(name:"IPMI password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"SMB account :", type:"entry", value:"");
 script_add_preference(name:"SMB password :", type:"password", value:"");
 script_add_preference(name:"SMB domain (optional) :", type:"entry", value:"");
 script_add_preference(name:"SMB password type :", type:"radio", value:"Password;LM Hash;NTLM Hash");

 for(var i=1 ; i <= MAX_ADDITIONAL_SMB_LOGINS ; i++)
 {
  script_add_preference(name:"Additional SMB account (" + i + ") :", type:"entry", value:"");
  script_add_preference(name:"Additional SMB password (" + i + ") :", type:"password", value:"");
  script_add_preference(name:"Additional SMB domain (optional) (" + i + ") :", type:"entry", value:"");
 }

 if(defined_func("MD5")) script_add_preference(name:"Never send SMB credentials in clear text", type:"checkbox", value:"yes");
 if(defined_func("MD5")) script_add_preference(name:"Only use NTLMv2", type:"checkbox", value:"no");
 script_add_preference(name:"Only use Kerberos authentication for SMB", type:"checkbox", value:"no");
 script_dependencies("kerberos.nasl", "pam_smb_auto_collect.nbin");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ssl_funcs.inc");
include("cyberark.inc");
include("cyberarkrest.inc");
include("beyondtrust.inc");
include("lieberman.inc");
include("hashicorp.inc");
include("arcon.inc");
include("thycotic.inc");
include("centrify.inc");
include("wallix.inc");
include("delinea.inc");
include("senhasegura.inc");
include("qianxin.inc");
include("fudo.inc");
include("ms_graph_api.inc");
include("debug.inc");

global_var result_list;

result_list = make_list();

if (get_kb_item("TEST/is_test"))
{
  result_list = get_kb_item("TEST/test_list");
  if (result_list)
    result_list = deserialize(result_list);
  else
    result_list = make_list();
}

#####
### Credential Values
#####

##
# HTTP
##
function http_credential_setup()
{
  local_var http_login, http_password, userpass, userpass64, authstr;

  http_login = script_get_preference("HTTP account :");
  http_password = script_get_preference("HTTP password (sent in clear) :");
  if (http_login)
  {
   if(http_password)
   {
    set_kb_item(name:"http/login", value:string(http_login));
    set_kb_item(name:"http/password", value:string(http_password));

    userpass = http_login + ":" + http_password;
    userpass64 = base64(str:userpass);
    authstr = "Authorization: Basic " + userpass64;
    set_kb_item(name:"http/auth", value:authstr);
   }
  }

  return NULL;
}

##
# NNTP
##
function nntp_credential_setup()
{
  local_var nntp_login, nntp_password;

  # NNTP
  nntp_login = script_get_preference("NNTP account :");
  nntp_password = script_get_preference("NNTP password (sent in clear) :");
  if (nntp_login)
  {
   if(nntp_password)
   {
    set_kb_item(name:"nntp/login", value:nntp_login);
    set_kb_item(name:"nntp/password", value:nntp_password);
   }
  }
}

##
# FTP
##
function ftp_credential_setup()
{
  local_var ftp_login, ftp_password, ftp_w_dir, ftp_auth_info;

  # FTP
  ftp_login = script_get_preference("FTP account :");
  ftp_password = script_get_preference("FTP password (sent in clear) :");
  ftp_w_dir = script_get_preference("FTP writeable directory :");

  ftp_auth_info = ftp_login+ftp_password;
  if (supplied_logins_only && ftp_auth_info == "anonymousnessus@nessus.org")
  {
    return NULL;
  }
  else
  {
    if (!ftp_w_dir) ftp_w_dir=".";
    set_kb_item(name:"ftp/writeable_dir", value:ftp_w_dir);
    if(ftp_login)
    {
      if(ftp_password)
      {
        set_kb_item(name:"ftp/login", value:ftp_login);
        set_kb_item(name:"ftp/password", value:ftp_password);
      }
    }
  }
}

##
# pop2
##
function pop2_credential_setup()
{
  local_var pop2_login, pop2_password;
  # POP2
  pop2_login = script_get_preference("POP2 account :");
  pop2_password = script_get_preference("POP2 password (sent in clear) :");
  if(pop2_login)
  {
   if(pop2_password)
   {
    set_kb_item(name:"pop2/login", value:pop2_login);
    set_kb_item(name:"pop2/password", value:pop2_password);
   }
  }
}

##
# POP3
##
function pop3_credential_setup()
{
  local_var pop3_login, pop3_password;

  pop3_login = script_get_preference("POP3 account :");
  pop3_password = script_get_preference("POP3 password (sent in clear) :");
  if(pop3_login)
  {
   if(pop3_password)
   {
    set_kb_item(name:"pop3/login", value:pop3_login);
    set_kb_item(name:"pop3/password", value:pop3_password);
   }
  }
}

##
# IMAP
##
function imap_credential_setup()
{
  local_var imap_login, imap_password;

  imap_login = script_get_preference("IMAP account :");
  imap_password = script_get_preference("IMAP password (sent in clear) :");
  if(imap_login)
  {
   if(imap_password)
   {
    set_kb_item(name:"imap/login", value:imap_login);
    set_kb_item(name:"imap/password", value:imap_password);
   }
  }
}

##
# IPMI
##
function ipmi_credential_setup()
{
  local_var ipmi_login, ipmi_password;

  ipmi_login = script_get_preference("IPMI account :");
  ipmi_password = script_get_preference("IPMI password (sent in clear) :");
  if(ipmi_login)
  {
    if(ipmi_password)
    {
     set_kb_item(name:"ipmi/login", value:ipmi_login);
     set_kb_item(name:"ipmi/password", value:ipmi_password);
    }
  }
}

##
# SMB
##
function smb_credential_setup()
{
  local_var smb_login, smb_password, smb_password_type, results_array,
  p_type, smb_domain, smb_ctxt, smb_ntv1, kdc_host, kdc_port,
  kdc_transport, kdc_use_tcp, j, i, smb_creds_prefix, smb_creds_postfix;

  var only_ntlmv2 = get_preference("Login configurations[checkbox]:Only use NTLMv2");
  var never_cleartext = get_preference("Login configurations[checkbox]:Never send SMB credentials in clear text");

  if(only_ntlmv2 == "yes" || never_cleartext == "yes")
    set_kb_item(name:"SMB/dont_send_in_cleartext", value:TRUE);

  if(only_ntlmv2 == "yes")
    set_kb_item(name:"SMB/dont_send_ntlmv1", value:TRUE);

  j = 0;
  for ( i = 0 ; i <= MAX_ADDITIONAL_SMB_LOGINS || (defined_func("nasl_level") && nasl_level() >= 6000); i ++ )
  {
    # The loop condition will succeed if i is less than MAX_ADDITIONAL_SMB_LOGINS or the nessus version is greater
    # than 6.0 . This work with a check at the end of the loop to verify that if it is greater than 6.0 we break
    # on the first set of null credentials.

    if (i > 0)
    {
      smb_creds_prefix = "Additional ";
      smb_creds_postfix = " (" + i + ") :";
    }
    else
    {
      smb_creds_prefix = "";
      smb_creds_postfix = " :";
    }

    smb_login = script_get_preference(smb_creds_prefix+"SMB account"+smb_creds_postfix);
    smb_password = script_get_preference(smb_creds_prefix+"SMB password"+smb_creds_postfix);
    smb_domain = script_get_preference(smb_creds_prefix+"SMB domain (optional)"+smb_creds_postfix);

    # In nessus >= 6 there can be different kerberos settings for each set of creds.
    # if nessus < 6, data read by kerberos.nasl is used for all creds
    kdc_host = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC"+smb_creds_postfix);
    kdc_port = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC Port"+smb_creds_postfix);
    kdc_transport = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC Transport"+smb_creds_postfix);
    kdc_use_tcp = FALSE;
    if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
      kdc_use_tcp = TRUE;

    # this new preferences will be introduced along with Nessus 6. in order to
    # maintain backwards compatibility with policies created under older scanners,
    # the password type set by the original preference (see SMB/password_type/0 above)
    # will be used as the default value for all additional SMB accounts
    if (script_get_preference(smb_creds_prefix+"SMB password type"+smb_creds_postfix))
    {
      smb_password_type = script_get_preference(smb_creds_prefix+"SMB password type"+smb_creds_postfix);
    }
    else
    {
      smb_password_type = "";
    }

    if ("Password" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Password");
      p_type = 0;
    }
    else if ("NTLM Hash" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"NTLM Hash");
      p_type = 2;
    }
    else if ("LM Hash" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"LM Hash");
      p_type = 1;
    }
    else if ("CyberArk" >< smb_password_type)
    {
      if (script_get_preference(smb_creds_prefix+"SMB CyberArk Host"+smb_creds_postfix))
      {
        set_kb_item(name:"target/auth/method", value:"CyberArk");
        smb_password = cark_get_password(login:smb_login, domain:smb_domain, prefix:smb_creds_prefix + "SMB ", postfix:smb_creds_postfix);
        p_type = 0;
      }
      else if ("Auto-Discovery" >< smb_password_type)
      {
        var pam = cyberark_auto_collect::pam;
        var kb_path = "/auto_smb/";

        # set parameter vars for AIM Webservice query to fetch password
        var object = get_kb_item(pam + kb_path + "object");
        var safe = get_kb_item(pam + kb_path + "safe");
        var address = get_kb_item(pam + kb_path + "address");
        smb_domain = get_kb_item(pam + kb_path + "domain");
        smb_login = get_kb_item(pam + kb_path + "username");

        if (empty_or_null(object) || empty_or_null(safe) || empty_or_null(address))
        {
          spad_log(message:"Host did not contain 1 or more CyberArk query parameter values. Will not attempt to retrieve password.");
        }
        else
        {
          var ca_result = cyberark_auto_collect::get_AIM_secret(settings:"Login configurations", prefix:smb_creds_prefix + "SMB ", postfix:smb_creds_postfix, safe:safe, username:smb_login, address:address, object:object);
          if (!ca_result.success)
          {
            spad_log(message:"Failed to retrieve password for CyberArk Windows Host.");
          }
          else
          {
            smb_password = ca_result.password;
            p_type = 0;
          }
        }
      }
      else
      {
        set_kb_item(name:"target/auth/method", value:"CyberArk REST");
        local_var cyberark_result;
        smb_creds_prefix += "SMB PAM ";
        cyberark_result = cyberark::cyberark_rest_get_credential(username:smb_login, domain:smb_domain, prefix:smb_creds_prefix, postfix:smb_creds_postfix);
        if (cyberark_result.success)
        {
          smb_password = cyberark_result.password;
          smb_login = cyberark_result.username;
          smb_domain = cyberark_result.domain;
        }
        p_type = 0;
      }
    }
    else if ("Thycotic" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Thycotic");
      smb_password = thycotic_smb_get_password(account:smb_login, prefix:smb_creds_prefix, postfix:smb_creds_postfix);
      p_type = 0;
    }
    else if ("BeyondTrust" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"BeyondTrust");
      var beyondtrust_result;
      beyondtrust_result = beyondtrust::get_password(login:smb_login, prefix:smb_creds_prefix + "SMB ", postfix:smb_creds_postfix);
      if(beyondtrust_result.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved BeyondTrust PAM SMB credentials.");
        smb_password = beyondtrust_result.body;
        if (beyondtrust_result.domain)
        {
          smb_domain = beyondtrust_result.domain;
        }
        p_type = 0;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Failed to retrieve BeyondTrust PAM SMB credentials.");
      }
    }
    else if ("Lieberman" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Lieberman");
      smb_password = lieberman_get_password(login:smb_login, type: "OS_Windows", domain:smb_domain, prefix:smb_creds_prefix + "SMB ", postfix:smb_creds_postfix);
      smb_password = smb_password.body.Password;
      p_type = 0;
    }
    else if ("Centrify" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Centrify");
      local_var centrify_result;
      centrify_result = centrify_get_credential(username:smb_login,prefix:smb_creds_prefix+"SMB ",postfix:smb_creds_postfix);
      if (centrify_result.success){
        smb_password = centrify_result.password;
        smb_login = centrify_result.username;
        p_type = 0;
      }
    }
    else if ("Hashicorp" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Hashicorp");
      local_var hashicorp_result;
      hashicorp_result = hashicorp::get_credential(username:smb_login,prefix:smb_creds_prefix+"SMB ",postfix:smb_creds_postfix);
      if (hashicorp_result.success){
        smb_password = hashicorp_result.password;
        smb_login = hashicorp_result.username;
        if (!empty_or_null(hashicorp_result.domain)) smb_domain = hashicorp_result.domain;
        p_type = 0;
      }
    }
    else if ("Arcon" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Arcon");
      local_var arcon_result;
      arcon_result = arcon::get_credential(username:smb_login, prefix:smb_creds_prefix+"SMB ", postfix:smb_creds_postfix, type:'Windows');
      if (arcon_result.success){
        smb_password = arcon_result.password;
        smb_login = arcon_result.username;
        p_type = 0;
      }
    }
    else if ("Wallix" >< smb_password_type)
    {
      set_kb_item(name: "target/auth/method", value:"Wallix");
      var wallix_result;
      wallix_result = wallix::rest_get_credential(prefix: smb_creds_prefix+"SMB ", postfix: smb_creds_postfix);
      if (wallix_result.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved Wallix PAM SMB credentials.");

        if (wallix_result.password)
        {
          smb_password = wallix_result.password;
        }
        if (wallix_result.username)
        {
          smb_login = wallix_result.username;
        }
        if (wallix_result.domain)
        {
          smb_domain = wallix_result.domain;
        }
        p_type = 0;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Failed to retrieve Wallix PAM SMB credentials.");
      }
    }
    else if("Delinea" >< smb_password_type)
    {
      set_kb_item(name: "target/auth/method", value:"Delinea");
      var delinea_result;
      delinea_result = delinea::rest_get_creds(prefix: smb_creds_prefix+"SMB ", postfix: smb_creds_postfix);
      if(delinea_result.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved Delinea Secret Server PAM SMB credentials.");

        smb_password = delinea_result.secrets.password;
        smb_login = delinea_result.secrets.username;
        if (delinea_result.secrets.domain)
        {
          smb_domain = delinea_result.secrets.domain;
        }
        p_type = 0;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Failed to retrieve Delinea Secret Server PAM SMB credentials.");
      }
    }
    else if ("Senhasegura" >< smb_password_type)
    {
      set_kb_item(name: "target/auth/method", value:"Senhasegura");
      var senha_result;

      senha_result = senhasegura::get_credential(prefix: smb_creds_prefix+"SMB PAM ", postfix: smb_creds_postfix);

      if(senha_result.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved Senhasegura PAM SMB credentials.");

        smb_login = senha_result.creds.username;
        smb_password = senha_result.creds.password;
        if (senha_result.creds.domain)
        {
          smb_domain = senha_result.creds.domain;
        }
      }
      else
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Failed to retrieve Senhasegura PAM SMB credentials.");
      }
    }
    else if ("QiAnXin" >< smb_password_type)
    {
      set_kb_item(name: "target/auth/method", value:"QiAnXin");
      var qax_result;

      qax_result = qianxin::get_credential(prefix: smb_creds_prefix+"SMB PAM ", postfix: smb_creds_postfix, default_platform:"WINDOWS");

      if(qax_result.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved QiAnXin PAM SMB credentials.");

        smb_login = qax_result.creds.username;
        smb_password = qax_result.creds.password;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Failed to retrieve QiAnXin PAM SMB credentials.");
      }
    }
    else if ("Fudo" >< smb_password_type)
    {
      var fudo_result = fudo::get_credential(prefix:smb_creds_prefix+"SMB PAM ", postfix:smb_creds_postfix);
      if (dbg::is_error(fudo_result))
      {
        dbg::log_error(msg:"Failed to retrieve Fudo PAM SMB credentials.");
      }
      else
      {
        dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:
          "Successfully retrieved Fudo PAM SMB credentials.");

        # Note that username and domain do not get retrieved from the integration.
        smb_password = fudo_result.password;
      }
    }

    else
    {
      set_kb_item(name:"target/auth/method", value:"None");
      p_type = 0;
    }

    dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'SMB Settings: \n'+
           "  credential type: " + smb_password_type + '\n' +
           "  username: " + smb_login + '\n' +
           "  domain: " + smb_domain + '\n' +
           "  password type: " + p_type + '\n' +
           "  kdc host: " + kdc_host + '\n' +
           "  kdc port: " + kdc_port + '\n' +
           "  kdc transport: " + kdc_transport + '\n' +
           "  kdc use tcp: " + kdc_use_tcp
           );

    results_array = make_array();

    if ( smb_login && smb_password )
    {
      results_array["SMB/login_filled/" + j] = smb_login;
      results_array["SMB/password_filled/" + j] = smb_password;
      results_array["SMB/domain_filled/" + j] = smb_domain;
      results_array["SMB/cred_type/" + j] = smb_password_type;
      results_array["SMB/password_type_filled/" + j] = p_type;

      if (kdc_host && kdc_port)
      {
        kdc_host = strip(kdc_host);
        results_array["SMB/kdc_hostname_filled/" + j] = kdc_host;
        results_array["SMB/kdc_port_filled/" + j] = int(kdc_port);
        results_array["SMB/kdc_use_tcp_filled/" + j] = kdc_use_tcp;
      }
      result_list[j] = results_array;
      j ++;
    }
    else if (i >= MAX_ADDITIONAL_SMB_LOGINS)
    {
      # Break at the first null credential that is above the max count of 3 for any version
      # of nessus. This is important for nessus versions greater than 6.0 .
      break;
    }
  }
}

##
# Attempts to authorize and pull LAPS credentials from Azure/Entra
#
# @remark
# Uses the Microsoft Graph API Library (includes/ms_graph_api.inc)
#
# Results are appended to the Global ``result_list`` as additional SMB credentials
#
# Pulls info from the following Preferences:
#   - "Microsoft Azure Settings[entry]:Tenant ID :"
#   - "Microsoft Azure Settings[entry]:Client ID :"
#   _ "Microsoft Azure Settings[password]:Client Secret :"
#
# @return [NULL]
##
function laps_credentials_setup()
{
  var tenant, app_id, secret;
  var laps_creds, laps_login, results_array, j, i;

  # j = last index of SMB creds +1
  if (!isnull(keys(result_list)))
    j = max_index(keys(result_list));
  else j=0;

  # Only 1 Azure Cloud Services-Credential is permitted

  if (get_kb_item("TEST/is_test"))
  {
    tenant = get_kb_item("TEST/tenant");
    app_id = get_kb_item("TEST/app_id");
    secret = get_kb_item("TEST/secret");
  }
  else
  {
    tenant = get_preference("Microsoft Azure Settings[entry]:Tenant ID :");
    app_id = get_preference("Microsoft Azure Settings[entry]:Client ID :");
    secret = get_preference("Microsoft Azure Settings[password]:Client Secret :");
  }

  laps_creds = laps_get_credentials(tenant_id:tenant, app_id:app_id, client_secret:secret);

  if (!laps_creds)
    return NULL;

  for (i=0; i<max_index(laps_creds); i++)
  {
    dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'SMB Settings: \n'+
           "  credential type: Entra LAPS" + '\n' +
           "  username: " + laps_creds[i].accountName + '\n' +
           "  password type: " + 0 + '\n');

    results_array = make_array();

    results_array["SMB/login_filled/" + j] = laps_creds[i].accountName;
    results_array["SMB/password_filled/" + j] = laps_creds[i].password;
    results_array["SMB/cred_type/" + j] = "Entra LAPS";
    results_array["SMB/password_type_filled/" + j] = 0;

    result_list[j] = results_array;
    j++;
  }

  return NULL;
}

##
# SMB insert data gathered
##
function smb_insert_data()
{
  local_var rl, smbi;

  foreach rl (result_list)
  {
    foreach smbi (keys(rl))
    {
      set_kb_item(name:smbi , value:rl[smbi]);
    }
  }
}

http_credential_setup();
nntp_credential_setup();
ftp_credential_setup();
pop2_credential_setup();
pop3_credential_setup();
imap_credential_setup();
ipmi_credential_setup();
smb_credential_setup();
laps_credentials_setup();
smb_insert_data();
