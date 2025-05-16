#TRUSTED 2114479122013a451d11e000dd3a9b67f3e03a41afa9ab5632e6b51d213178009b12d7a63664af08a58925ac738f512a755c2243946d483e15874a727aaf5db343cbfa19017c8be080e91ba5916e2ad5ed4169ee528853d68053598ff804cccccd89747b603075481c1c6376d159bcbc53828625e7110d69ed0863b59fa844cee6372e0339f5540939178e711f039657fd5871c9539c267fe7d0b48516943fa4c22c34bbbcefc7205a538e54605953a2fe8bd4f1bd302c03bb7fd1905b0cef435a1c9919768f3ace56efc1195eab55847540cb72a3799b1b91e40f40641ab5300d061c5fc8efced22cad449de1b8c232fed4c75119f3f3753dbd0df845e19b9c502040b84933e0018f99373f21b4aa380d9af0dc62f907d9d1c5d6f2bbe7a999f87271593ad1b5e927d384ac6fb4b9cf161f801747b51103e290306ff1fa5a6b4b46acd02ee1c14056528115d330bb9313672293f136b0eb9da0a45bae317f7042009301517e5bef6dbe3d49de5a689971fbe910eedbe18d5221da63e3ae0cc18963bc6cacc42e1195b403f3383ea9dd9923d0b92288f898f657faaee290c4a7902d3c5ba9bbd9da4be37ad75f299ae7d3c9626588f3682357cd89a499c36bb515d002c257630ac906832b20004724f0fbf4d8a40736c1128dc022188d5ab86c7c6c572cfe4e69a16349501ba62e87df7bdb398605d32d4c2654f6587293ff86
#TRUST-RSA-SHA256 abcea1f8f66f9d6d42dbf416c5320bfb669a7f2f6a9999aa10b230246e880be8117877e8fc6d7bb6878f6ccb3eeb88c23c1373152c59e7a45a5047b1d3515d5cadffc7f8b21186f097ef115c4720df453f298938ba4c3261d1377b358379cf0ea1164bd8f8be12e0ce76fbadf9925d3151bb7631f7c5b5375fd5b3ddd1d7f8b1d6f33b697e1eddccf12c6c1a4aa1a1e91832b35c0a8d5278d27180de6072bcbed60a29a9a90ab8701284160ba18ffc779e477ec530b10d63a9bdadb34c13b486f51fb727270bf3933b85a3371a10691aa203751283ce06700ed8e827cb85de88f968cb87dec771262ed21c7f697649c554c828a9cf4bec77f57e94934cdd18f164d00500cea15beb8f84c0ed414487f1f1ce4ad99fdaedd4e7e3175ed018c33ac8c1850ed0a0bee3e815cf1c4d43e4e5cc3849f580dc856b158eec004383672459f3d3349feab1a741721e8982981aa772cad827339a0a74f5d5c91ee526da279bb492f894b361588b3ef411c9a06aae28a7da7d2d9c31a47f2091c8aa82b42922b71bdbfc536b6bb01e496c58d2e10a04aae9a5f16c96fe1d6c2231fbed610b01f3f59d0e1f09366c66eefec2c961eb244608e5944b447bbcda951ebd381096a0d76492af7a43b1164cb8f8ee526383e9280cfd10b5f043fab9418f19a528c00d07f0d89e58791297ff0490fbdcd29c04bac12e99957f7a0931560f2c6eaf69
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
#
# @NOGPL@
#
# windows_accounts_object.inc
#
# Revision: 1.5
###

include('compat_shared.inc');
include('spad_log_func.inc');
include('debug.inc');
include('smb_func.inc');
include('json2.inc');
include('debug.inc');

##
# Object representing a Windows user account.
##
object windows_accounts
{
  var accounts = {};
  ##
  # Some methods require an account key to operate on. This attribute holds the
  # key fo the account currently in focus.
  ##
  var account_in_focus = NULL;

  var sid_string_pattern = "^S-\d-\d+(?:-\d+){1,5}$";

  ##
  # Constructor to initialize the Windows accounts data structure.
  #
  # @anonparam [1st:array] Accepts an accounts data array to initialize the object.
  ##
  function windows_accounts()
  {
    if(typeof(_FCT_ANON_ARGS[0]) == 'array')
    {
      var valid = TRUE;
      for (var account of _FCT_ANON_ARGS[0])
      {
        if(!validate_windows_account_data(data:account))
        {
          valid = FALSE;
          break;
        }
      }

      if(valid)
        this.accounts = _FCT_ANON_ARGS[0];
    }
  }

  ##
  # Make an account and add it to the accounts data structure. 
  #
  # @param [key:string] String or hex SID.
  #
  # @return [boolean] TRUE if the account creation was successful, FAlSE otherwise.
  ##
  public function make_account(key)
  {
    var account = NULL;

    if(typeof(this.accounts[key]) == 'array')
    {
      this.account_in_focus = NULL;
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Attempted to create an account that already exists using key",
        msg_details: {
          "key": {"lvl": 1, "value": key}});
      return FALSE;
    }

    if(typeof(key) == 'data')
    {
      if(toupper(key) =~ this.sid_string_pattern)
        account = new_account_from_sid_string(sid:key);
      else
        account = new_account_from_sid_hex(sid:key);
    }
    else
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Invalid data type passed to windows_account object constructor.");
      return FALSE;
    }

    if(account)
    {
      this.accounts[account.sid] = account;
      this.accounts[account.sid].groupMembership = [];
      this.accounts[account.sid].password = {};
      this.account_in_focus = account.sid;
      return TRUE;
    }
    else
    {
      this.account_in_focus = NULL;
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Could not create account from provided key",
        msg_details: {
          "key": {"lvl": 1, "value": key}});
    }
    return FALSE;
  }
  
  ##
  # Get the account that is currently in focus.
  #
  # @return [array] Account data.
  ##
  public function get_focused_account()
  {
    if(!this.account_in_focus)
      return NULL;
    
    return this.accounts[this.account_in_focus];
  }

  ##
  # Check if an account exists for a given key.
  #
  # @param [key:string] Key value.
  #
  # @return [boolean] TRUE if the account exists, FALSE otherwise.
  ##
  public function account_exists(key)
  {
    if(key && typeof(this.accounts[key]) == 'array')
      return TRUE;
    
    return FALSE;
  }

  ##
  # Sets the account that the object will focus operations on.
  #
  # @param [key:string] Key value.
  #
  # @return [boolean] TRUE if the account exists, FALSE otherwise.
  ##
  public function focus_account(key)
  {
    if(account_exists(key:key))
    {
      this.account_in_focus = key;
      return TRUE;
    }

    this.account_in_focus = NULL;
    return FALSE;
  }

  ## 
  # Search accounts for an account by name and domain and return
  # the SID if known.
  #
  # @param [name:string] Name of the account.
  # @param [domain:string] Domain name of the account.
  #
  # @return Account SID, or NULL if no matching account was found.
  ##
  public function get_account_sid_by_name_domain(name, domain)
  {
    for( var account of this.accounts)
      if(account.name == name && account.domainName)
        if(account.sid && account.sid != 'unknown') return account.sid;
    return NULL; 
  }

  ## 
  # Sets the home directory for the account.
  #
  # @anonparam [1st:string] Home directory.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_home_directory(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].homeDirectory) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].homeDirectory = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Sets the type of the account. Domain or local.
  #
  # @anonparam [1st:string] Account type. Domain or local.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # devnote: See also 'accountType' (service vs user) below
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_type(overwrite)
  {
    if(!this.account_in_focus || (_FCT_ANON_ARGS[0] != 'local' && _FCT_ANON_ARGS[0] != 'domain') && _FCT_ANON_ARGS[0] != 'entraid')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].type) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].type = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Sets the type of the account. User or service.
  #
  # @anonparam Account type. User or service.
  #
  # devnote: See also 'type' (domain vs local vs entraid) above
  #
  # @return TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_accountType(overwrite)
  {
    if(!this.account_in_focus || (_FCT_ANON_ARGS[0] != 'user' && _FCT_ANON_ARGS[0] != 'service') )
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].accountType) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].accountType = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Sets the domain name that the account belongs to.
  #
  # @anonparam [1st:string] Domain name.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_domain_name(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].domainName) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].domainName = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Sets the account name(username).
  #
  # @anonparam [1st:string] Account name.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_name(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].name) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].name = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Get the account name(username)
  #
  # @return [string] Account name
  ##
  public function get_name()
  {
    if(this.account_in_focus)
      return this.accounts[this.account_in_focus].name;
  }

  ##
  # Set the focused account's AD distinguished name.
  #
  # @anonparam [1st:string] Distinguished name.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_distinguished_name(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].distinguishedName) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].distinguishedName = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's disabled status.
  #
  # @anonparam [1st:integer] Account disabled status. 1=TRUE, 0=FALSE
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_disabled(overwrite)
  {
    if(!this.account_in_focus || !(_FCT_ANON_ARGS[0] == 1 || _FCT_ANON_ARGS[0] == 0))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].disabled) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].disabled = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's lockout status value.
  #
  # @anonparam [1st:integer] Account disabled status. 1=TRUE, 0=FALSE
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_lockout(overwrite)
  {
    if(!this.account_in_focus || !(_FCT_ANON_ARGS[0] == 1 || _FCT_ANON_ARGS[0] == 0))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].lockout) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].lockout = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's logon time.
  #
  # @anonparam [1st:integer] Unix timestamp.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_logon_time(overwrite)
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].logonTime) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].logonTime = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's logoff time.
  #
  # @anonparam [1st:integer] Unix timestamp.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_logoff_time(overwrite)
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].logoffTime) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].logoffTime = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's account expiration time.
  #
  # @anonparam [1st:integer] Unix timestamp.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_expires_time(overwrite)
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].accountExpiresTime) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].accountExpiresTime = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's password can change attribute.
  #
  # @anonparam [1st:integer] Password can change status. 1=TRUE, 0=FALSE
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_password_can_change(overwrite)
  {
    if(!this.account_in_focus || !(_FCT_ANON_ARGS[0] == 1 || _FCT_ANON_ARGS[0] == 0))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password.passCanChange) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].password.passCanChange = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Get the focused account's password can change attribute.
  #
  # @return Password can change attribute value
  ##
  public function get_account_password_can_change()
  {
    if(this.account_in_focus)
      return this.accounts[this.account_in_focus].password.passCanChange;
  }

  ##
  # Set the focused account's password must change attribute.
  #
  # @anonparam [1st:integer] Unix timestamp or 0.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_password_must_change_time(overwrite)
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password.passMustChange) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].password.passMustChange = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's password last set time.
  #
  # @anonparam [1st:integer] Unix timestamp or 0.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_account_password_last_set_time(overwrite)
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password.lastChanged) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].password.lastChanged = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's User Account Control value.
  #
  # @anonparam [1st:integer] User Account Control as an int.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  #
  # @remark Windows represents the UAC value as a unit but they do not
  #         currently use the most significant bit. Nasl cannot properly
  #         serialize a uint to JSON so we ignore the most significant
  #         bit and treat it as an int.
  ##
  public function set_account_user_account_control(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]) || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].userAccountControl) && !overwrite)
      return FALSE;
    
    if(_FCT_ANON_ARGS[0] >= 0)
    {
      this.accounts[this.account_in_focus].userAccountControl = _FCT_ANON_ARGS[0];
      return TRUE;
    }
    return FALSE;
  }

  ##
  # Add a group sid to the focused account's group membership.
  #
  # @anonparam [1st:string] Group sid.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function add_group_membership_sid()
  {
    if(!this.account_in_focus || _FCT_ANON_ARGS[0] !~ this.sid_string_pattern)
      return FALSE;

    # check if group sid already in groupMembership
    if ( contains_element(var:this.accounts[this.account_in_focus].groupMembership, value:_FCT_ANON_ARGS[0]) )
      return FALSE;

    append_element(var: this.accounts[this.account_in_focus].groupMembership, value:_FCT_ANON_ARGS[0]);
    return TRUE;
  }

  ##
  # Dump the account data structure to JSON.
  #
  # @return [string] JSON blob containing the account data.
  ##
  public function json_dump()
  {
    return json_write(this.accounts);
  }

  ##
  # Call report_tag_internal() to save the user data structure to the db.
  #
  # @return NULL
  ##
  public function report()
  {
    if(defined_func("report_tag_internal"))
    {
      var env = nasl_environment(flags:ENV_PLUGIN);
      if (!empty_or_null(env['plugin_id']))
      {
        report_tag_internal(
          tag:strcat('identity-windows-accounts:', env['plugin_id'], ':local:tcp'),
          value:this.json_dump());
        dbg::detailed_log(lvl:1, msg:'Accounts: '+ obj_rep(this.json_dump()));
      }
    }
  }

  ##
  # Initialize the account data structure from a SID string.
  #
  # @param [sid:string reference] The SID of the new account.
  #
  # @return [array] An array containing the given SID.
  ##
  private function new_account_from_sid_string(&sid)
  {
    return {
      'sid': toupper(sid)
    };
  }

  ##
  # Initialize the account data structure from a hex SID.
  #
  # @param [sid:data reference] The SID of the new account.
  #
  # @return An array containing the given SID in string form, or NULL if an error occurred.
  ##
  private function new_account_from_sid_hex(&sid)
  {
    var sid_string = 'S-' + sid2string(sid:sid);
    if(sid_string !~ this.sid_string_pattern)
    {
      if(sid_string == 'S-')
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not convert SID from hex to string.");
      else
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "SID is not valid.");
      return NULL;
    }

    return {
      'sid': sid_string
    };
  }

  ##
  # Perform a set of validation steps to ensure the account data is 
  # correct.
  #
  # @param [data:array reference] The account array to validate.
  #
  # @return [boolean] TRUE if the account data is valid, FALSE otherwise.
  ##
  private function validate_windows_account_data(&data)
  {
    if(
      data.sid =~ this.sid_string_pattern
    ) return TRUE;
    
    return FALSE;
  }
}
