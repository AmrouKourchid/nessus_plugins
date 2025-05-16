#TRUSTED 86a423469bf4b2a0399c15b16448d89a561cde4cfe3c04b9654d7ea80c7e79c03843af909bea7dbe66bc968e553f52e5324e65a976184ff91678a237e563a0122c499241abf5b239d607d9160651887c7355cfa4afdb63cb09264c6a4bf4206d37cbcffdc9f7edafab99f91e2f2314aae02d2db4315ae3308e9b0af13cdd586505ffcdd8b469bc81dd7f8400586cbed6c34e08c33ee7d126c41d0fb65fcb1a3726c1e198408211b256a215045b55ac6b526e56e05e016826ae86853536682754a84c29cf5b731d2a3917f19bb67e9f890b9f2e79763b3301fcdee0b4142ef2be11fdd5e9cb1eb76072e9c8e794d94d84dcf11d3f79c264691a329dc76c250c7ae0bae50009ad9f2fdb042bd0f970d3a1041eb3a96c5e1a342d5fe8d845a2bf9e2c4147e0a50afb16cbfcb6d2ab428c4ed2ce648352a68e3d144d91b17454096c9f6d70c9fa5c83a974ebf534a760314382476b499a14596e5c99a840470e02b99da067672da11656c0842185d4ed83ba38ad11aed12093235da0943e005d08bab3f89fe6fa14e7c334b6aeb25fb91c53e1526e7a66fd055779aae67b356f544f0ef252ff4d8779b05ef95c5a41c055645589a3cf3f901995dd703e21d1c58d8f5c49f2256556ca5a8251481b39755355da6cbff414e5f7f8ef65b25892e66e10ace6e6dc64127b4a1963e5af950ced206e0513fc9bd2466c953311da2d6d5c3d
#TRUST-RSA-SHA256 47ab7a1a8fcfe4631ec02305661da1348adea7a712fe461a97e15ccda983660b6513e8768e3b45809ce057533601d37b51824f15e7288fdbb3d6f80f9da70b10101903c83b7e0eedf7037e62f2d002ce601c8c2644eae42e8e5acc95c20fe09710cd7cb91fc252d9cb34106f08cd343fb6201eac7923a281cd60fc78da2fb54357b6f85868a7ed16fb688dd5c29d182c0be98d3f299f2071bd9a969ff6a8e57cf89aaac459ecc13216bf6fc06b9b8401ed55883104061f7736213ba2512249dc06834b89603c73aa868f46c6fba3df3e01fdfb1b7ff9b0f037e299b29d7dd02e4f1743d30fe1a8cb66d4896220b82d59c66228c4bc553aeccf71590714fe9497e1d3cb42412049084fcd1db08c44abda97d1a4cad5b3f7fec58a1a613c327213a82a5d068c0197d8130f2ca5a6aca266de0c4a254b56935d9365b04f003b73ecf5b2f10b2a626976b0b02ae4874a7e0e2d408f918a10ea0149bd0cfd2fb4807869e9c477f2e2c649db2e9fb0bee71a6c1bfaa6838a152584b4b03524180944db964aa9828f0cddad18f88333f79aedaae65a9f9ce127a1c1661852653dfebb961085fe4cf76f62896509d2d71d20b692f030f35aeeca72d8fe0fe16f331ae57c2bbb29b6e925a5372b64273f750e46d488a9e1ac92fa5aac216a4ae99600cec0ce92868155da3e289b720e3368489d91d45ab59ee3c4e534526284f6e0ada0fe
#
# (C) Tenable Network Security, Inc.
#
# Revision: 1.3

include("compat_shared.inc");

##
# Generates report text describing the credential used
# for local checks in the current scan.
#
# @param [proto:string]    An abbreviation of the authentication protocol (SMB, SSH, SOAP, etc)
# @param [port:interger]   The target host port used for local access.
# @param [user:string]     The username used to authenticate the target.
# @param [oneline:boolean] Flag instructing the function to compose a one-line description of
#                          the credential
# @return Returns a credential description.
# @remark This function is intended for use by ACT_END plugins.
##
function get_credential_description(proto, port, user, oneline)
{
  var desc = '';
  var login_used;
  var cred_type, auth_method, escl_type;
  var provided_by = FALSE;

  cred_type = auth_method = escl_type = NULL;

  if(isnull(oneline))
    oneline = FALSE;

  if(!isnull(proto))
    proto = toupper(proto);

  if(proto == 'SMB')
    login_used = get_kb_item("HostLevelChecks/smb_login");
  else if(proto == 'SNMP')
    login_used = user;
  else
    login_used = get_kb_item("HostLevelChecks/login");

  # HostLevelChecks/logins KB item does not exist when local checks are enabled 
  # via ssh_rate_limiting. The username can be passed directly via the 'user'
  # param in this scenario.
  if (empty_or_null(login_used) && !isnull(user))
    login_used = user;
  
  if(!empty_or_null(login_used))
  {
    if(!oneline)
      desc = 'User:       ';

    desc += "'" + login_used + "'";

    if(!oneline)
    {
      desc += '\n';
      if(!empty_or_null(port))
        desc += "Port:       " + port + '\n';
    }

    if(proto == 'SMB')
    {
      cred_type = get_kb_item("HostLevelChecks/cred_type");

      if(get_kb_item("SMB/only_use_kerberos"))
        cred_type = "Kerberos";

      if(cred_type == "NTLM_Hash")
        auth_method = "NTLM hash";
      else if(cred_type == "LM_Hash")
        auth_method = "Lanman hash";
      else if(cred_type == "Kerberos")
        auth_method = "gssapi";
      else
        auth_method = "password";
    }
    else if(proto == 'SSH')
    {
      escl_type = get_kb_item("HostLevelChecks/escl_method");
      cred_type = get_kb_item("HostLevelChecks/cred_type");
      auth_method = get_kb_item("HostLevelChecks/auth_method");
    }

    if(!empty_or_null(proto))
    {
      if(oneline)
        desc += " via " + proto;
      else
        desc += "Proto:      " + proto + '\n';
    }

    if(!empty_or_null(auth_method))
    {
      if(oneline)
        desc += " with " + auth_method + " authentication";
      else
        desc += "Method:     " + auth_method + '\n';
    }

    #Credentials can be provided by password managers and a public key can be provided by a certificate
    if(!empty_or_null(cred_type) &&
       tolower(cred_type) != "password" &&
       cred_type != "LM_Hash" &&
       cred_type != "NTLM_Hash" &&
       cred_type != "Kerberos" &&
       cred_type != "public key" &&
       auth_method != "none")
    {
      if(oneline)
        desc += " provided by " + cred_type;
      else
        desc += "Source:     " + cred_type + '\n';
    }

    if(!empty_or_null(escl_type))
    {
      if(oneline)
        desc += ", using " + escl_type + " escalation";
      else
        desc += "Escalation: " + escl_type + '\n';
    }
  }
  else if(proto == "LOCAL")
  {
    if(oneline)
      desc = " (on the localhost)";
    else
      desc += "Proto: local access";
  }

  return desc;
}

