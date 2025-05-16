#TRUSTED 01986c2b930a0c51acdd88b27c72330ccddc6b74f49ecca4cd85f1ce1d3c66fda855119be5eb3eae4829f85ad6289c6d240025fe9f6e5ef247e7af93058b0badb035b6afe9394016c30389832c77040998c0cb59e8b63a8a7f9f4528428a23ef94921909072fe8f0b4968c7a23e0eb873c080ca3e57fc4d497feb994bd251541f6a4eeb66e8d1888cece0dd62dbaf9aa928112fe578028ca367ab6e9e3b449dd194bd581c2fbd15f32b0cb2647fae2574df187350aa65eb0f4d9734688781d1c6bd00f6fb5d114e36598adfb064a0a1bb9031fe8f0fe120371e99ac8aaf1d29f89d381645c171402c88e94e920cb0dfc226be1f984118ec19c958333168588e55b6ca0fb5d7f32eb91171175d78c2764cf8f0a7447391ea32648b247eb4287f836cab8ad802292c4591d69f838c305d241fc2694102e596516647b52a68b0fa1e912cfd6250f68b2800b4f817218d3acdf5ed00984e9aa265337a6f651c8f65164b9ce9b845608fc1431f5bf7122c87dc04791c380e87bc6af19f96ef805e45d83336b575c4ad2add194c096dd02f2728af4823664bb5c7c5ef658617e8846f6d44888b2855d18652374d5361a34e85b555fa3432951a20957557f7b3e092ce5f2ed11140aebe6d27484078d10220ebe3673cc07800f28a95ccc479f61b65a8948a2755cff2bb5bfad529b977527cad07c076b74bf8deaf4ac0d25f46ecbc9bd
#TRUST-RSA-SHA256 ac27dbe7c5006ce5aae9c113de98c30499cc5bd35d5cf410dc2e6e0a7e3154c22d9cd36d8a99430ccbf0adad0fc394d1ee68701511c76111b4df37b71500eb43d52c4c37e2c511bce405eae29784fc2ab96a0dad84304fd1e73e1bf88e00ffb3f31f719a6c70f5f8224a76e127e3a5aa2ec15f8c640b81d6b062c9d83ea5e66e078b8f4f06ad8a7f29f1dc78a8e37191ed857e0f584ed03240857925c537161eb9a3c9af5ea4887ac97457a520e6c8ddbed715d24aa5684400a994eeb7c41446d89bca2cbf90a5ab5a2f5fb31a0bd979beda0dc167d082a153dc32ee86a0527e0202729eecfcd958ef5595c28e2fc4e35c91f22bcd169327cf9cb1f9f363bd0a665814353669908827276ce9daf266c039faee54c7b95d763888bd78f9071b2f8e70fbde0fe2362597c60daedec6056c2d8ea53843e7fbe10cee5a8c4843df905ea8b705b43314e677a92f2e65241e9d6a7e4c6e09acd67b1a9a1078f629cd3306e866cdfc1074010d193d04c3a27dadb6d8957c94f6d9728e07a847d08239dc9e15eca3cb26fd30aaca806a8f220202cce32fc965a6c902841fc0b0bb372c83d1c1236248bf0774cd8c32d9fa42577840a5f56f014c803f516a7a1406ee8fc215325745f8fbc6c2f63d7bc296e03d1e1cc06490c1349d09edd81472ae720791406df98987abac31ee280c8e63ac6e822cb5fc4dd56517dbce93520b29bea54f
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
# linux_accounts_object.inc
#
# Revision: 1.6
###
include('debug.inc');
include('json2.inc');

##
# Object representing a set of Linux user accounts.
##
object linux_accounts
{
  var accounts = {};
  ##
  # This attribute holds the key of the account currently in focus.
  ##
  var account_in_focus = NULL;

  ##
  # Make an account and add it to the accounts data structure. 
  #
  # @param [key:integer] User id(uid).
  #
  # @return [boolean] TRUE if the function was successful, FALSE otherwise
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

    if(typeof(key) == 'int')
    {
      account = new_account_from_uid(uid:key);
    }
    else
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Invalid data type passed to linux_accounts object constructor.");
      return FALSE;
    }

    if(account)
    {
      this.accounts[account.uid] = account;
      this.accounts[account.uid].groupMembership = [];
      this.accounts[account.uid].password = {};
      this.accounts[account.uid].lastlog = {};
      this.account_in_focus = account.uid;
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
  # @return [array] Account data. NULL if there is no account in focus.
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
  # @param [key:integer] string Key value.
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
  # @param [key:integer] Key value.
  #
  # @return [boolean] TRUE if succcessful, FALSE otherwise.
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
  # Sets the account type for the focused account.
  #
  # @anon_param boolean TRUE/FALSE regarding if user account or not.
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_accountType(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;

    if(!isnull(this.accounts[this.account_in_focus].type) && !overwrite)
      return FALSE;

    if (_FCT_ANON_ARGS[0])
      this.accounts[this.account_in_focus].accountType = 'user';
    else
      this.accounts[this.account_in_focus].accountType = 'service';
    
    return TRUE;
  }

  ##
  # Set the scope for the account in focus. Domain or local.
  #
  # @anon_param [1st:string] Account scope. Domain or local.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_account_scope(overwrite)
  {
    if(!this.account_in_focus || (_FCT_ANON_ARGS[0] != 'local' && _FCT_ANON_ARGS[0] != 'domain'))
      return FALSE;

    if(!isnull(this.accounts[this.account_in_focus].scope) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].scope = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ## 
  # Sets the home directory for the focused account.
  #
  # @anon_param [1st:string] Home directory.
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
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
  # Sets the command shell for the focused account.
  #
  # @anon_param [1st:string] Command shell path.
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_command_shell(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].commandShell) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].commandShell = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Sets the name(username) for the focused account.
  #
  # @anon_param [1st:string] Account name.
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
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
  # @return Account name
  ##
  public function get_name()
  {
    if(this.account_in_focus)
      return this.accounts[this.account_in_focus].name;
  }

  ##
  # Set the focused account's expired status.
  #
  # @anon_param [1st:boolean] Account expired status. 1=TRUE, 0=FALSE
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE on success. FALSE if there was a problem.
  ##
  public function set_account_expired(overwrite)
  {
    if(!this.account_in_focus || !(_FCT_ANON_ARGS[0] == 1 || _FCT_ANON_ARGS[0] == 0))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].expired) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].expired = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's logon time
  #
  # @anon_param [1st:integer] Unix timestamp
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE on success. FALSE if there was a problem.
  ##
  public function set_account_logon_time(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].logonTime) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].logonTime = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's password locked status.
  #
  # @anon_param [1st:boolean] The lock status
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE on success. FALSE if there was a problem
  ##
  public function set_account_password_locked(overwrite)
  {
    if(!this.account_in_focus ||  !(_FCT_ANON_ARGS[0] == 1 || _FCT_ANON_ARGS[0] == 0))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password.locked) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].password.locked = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's password never changed status.
  #
  # @anon_param [1st:boolean] The password change status
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE on success. FALSE if there was a problem
  ##
  public function set_account_password_never_changed(overwrite)
  {
    if(!this.account_in_focus ||  !(_FCT_ANON_ARGS[0] == 1 || _FCT_ANON_ARGS[0] == 0))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password.neverChanged) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].password.password.neverChanged = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's password never expires status.
  #
  # @anon_param [1st:boolean] The password expiration status
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE on success. FALSE if there was a problem
  ##
  public function set_account_password_never_expires(overwrite)
  {
    if(!this.account_in_focus ||  !(_FCT_ANON_ARGS[0] == 1 || _FCT_ANON_ARGS[0] == 0))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password.neverExpires) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].password.password.neverExpires = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's password expiration date time.
  #
  # @anon_param [1st:integer] Unix timestamp or 0.
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE on success. FALSE if there was a problem
  ##
  public function set_account_password_expiration_date(overwrite)
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password.expirationDate) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].password.expirationDate = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's password last change time.
  #
  # @anon_param [1st:integer] Unix timestamp or 0.
  #
  # @param overwrite boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE on success. FALSE if there was a problem
  ##
  public function set_account_password_changed_time(overwrite)
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password.lastChanged) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].password.lastChanged = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Add a group id to the focused account's group membership.
  #
  # @anon_param [1st:integer] Group id.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function add_group_membership()
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;

    append_element(var: this.accounts[this.account_in_focus].groupMembership, value:_FCT_ANON_ARGS[0]);
    return TRUE;
  }

  ##
  # Dump the account data structure to JSON.
  #
  # @return JSON blob containing the account data.
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
      report_tag_internal(tag:'identity-linux-accounts:95928:local:tcp', value:this.json_dump());
  }

  ##
  # Initialize the account data structure from a UID.
  #
  # @param [uid:integer reference] The UID of the account
  #
  # @return An array containing the UID, FALSE if a problem occurred
  ##
  private function new_account_from_uid(&uid)
  {
    if(typeof(uid) != 'int')
      return FALSE;
    
    return {
      'uid': uid
    };
  }

  ##
  # Perform a set of validation steps to ensure the account data is 
  # correct.
  #
  # @param [data:array reference] The account data to validate
  #
  # @return [boolean] TRUE if the data is valid, FALSE otherwise
  ##
  private function validate_linux_account_data(&data)
  {
    if(
      typeof(data.uid) == 'int'
    ) return TRUE;
    
    return FALSE;
  }
}
