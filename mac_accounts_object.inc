#TRUSTED 2f50bab51b6b65019a0ed3e6a0bf1ef938abcd5bc41a22a6a013b94c97d0c678db8365926cb1fe0653f1d10c7be436cf55032b3089ca34449380d47348227121e58aa28e3c34c6829c1f8fc0fba76aab59c82055579d0aa4fde6b3ad6ce371685335e0e2fa1f00c2dc2cc84dd674d8e7dfd3613b4d36d8d6564dc33ffc14298c42702c9df52756a8027c88add85512e009ad976b5c128ae4fb6c3221e964e7b3954a300723474b31067e0d0f1bd13796d345a0d8e1e4a8f99f565e49d87478155c59326c9edcad9de2b027c242a3dd10179bc6780e6242a80b0aa29aba5ef674aaf2b58786068c6017b80dfb33c376bb0dc392f5ed4e008c096e763e8ab83946be38e9011538da5fbb28435c3f8d965164720169592d08b642170f5ec939d82adc12d320e43d8d13663490c22e8a2b449edb37581e0eb78f72351c4aefbd7079db0f7f95c289276ef45e3dd6463a8ebb998f9da7f7c536532027b2aa6704c30e8ddda7051f61ecff7521504913a4cd8fa0b9d2da22e2afc252fa3ae7abb997aaded86af42ca09a069d93791053aa7aa64c3f7258bf3e7a1818891a580d2ce20770596c4d34670d696e7a63c308d1df554c7ef0a05005c1411e98b8a841eee23e5f1c4ede93ee4b3166eec1ce75d4d407ee7363fa6c11e0c2afa0f2e8045f8cd7b71b1ddd0c26088fd7091d5367a619ac06683f771a8fc28a3177acd883f41e18
#TRUST-RSA-SHA256 63f2e24c4abbd8f52c3b5bf82734baf02dd43f40b9349f8fc6439b4b710ca4ff1f7cc892e1f29cfb19b6f4aa65c53138867d5bbab9831fc2563e85079e3baf6a7964f9879c42baea639cabb5272f30b976c5814b5065881c058466d23c82dbb297fa0f024d455cb19fd6e9cd01732929e1c1fa1f115babaf4b30172418e3ee81901d4c526be20692ab82d0568345f1ac24687aec7fd61d163c80325d6be1233d5213bae2a80d812694163b0b46914b915238a36c7911e13dddc89125edf985b93c9bde7b526e695068fb08aecb9b836bbd6fd4947451c212067533e7751c7b203b04cc140425a750cede82fe900061eb2c97474c2ec56cfddf6cbe70a0d537bf2419523eb98c1a1076f032c17c8ecdc148c5fcc082122e8f797379556ecf97e169c6d35be72a703a553688570460486c286f5c776e93a06f33287a770b2fd218f6ff0473ae6e199086945cae6deafc3885e8676c6f81b682e78ad0ff22bb93dfbe4acd7fcff129cdd895b627068f4e8a5e32ae1773a3a671c11641cab71deae42baf818d58999e44b3a01d4cb74720648394d0a97b3b258b4ee87d6fe3692d16ab8fd4e3f0ecb05fbb52add60665fa67eae32e50d3ef0da3dfb3dfcbf3cf89b44dee4e71b692de14e2211dfda4931cbeb3a2914cdc191994e696f036da38094bfe12bc80c85cd99ba463439d3fe0fa7102f53212909588cab0d7608a012ead80
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
# mac_account_object.inc
#
# Revision: 1.4
###
include('debug.inc');
include('json2.inc');

##
# Object representing a set of Mac user accounts.
##
object mac_accounts
{
  var accounts = {};
  ##
  # This attribute holds the key of the account currently in focus.
  ##
  var account_in_focus = NULL;

  var guid_string_pattern = "^[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}$";

  ##
  # Make an account and add it to the accounts data structure. 
  #
  # @param [key:string] User id(GeneratedUID).
  #
  # @return [boolean] TRUE if the account was created, FALSE otherwise.
  ##
  public function make_account(key)
  {
    var account;
    this.account_in_focus = NULL;

    if(key =~ this.guid_string_pattern)
    {
      account = new_account_from_guid(guid:key);
    }
    else
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Invalid data type passed to make_account.");
      return FALSE;
    }

    if(account)
    {
      this.accounts[key] = account;
      this.accounts[key].groupMembership = [];
      this.account_in_focus = key;
      return TRUE;
    }
    else
    {
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
  # @return NULL.
  ##
  public function focus_account(key)
  {
    if(this.account_exists(key:key))
      this.account_in_focus = key;
    else
      this.account_in_focus = NULL;
  }

  ## 
  # Sets the home directory for the account in focus.
  #
  # @anon_param [1st:string] Home directory.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
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
  # Sets the unique user id for the account in focus.
  #
  # @anon_param [1st:integer] User id.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_uid(overwrite)
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].uid) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].uid = _FCT_ANON_ARGS[0];
    return TRUE;
  }

    ## 
  # Set the SMBSID for the account in focus.
  #
  # @anon_param [1st:integer] The SMBSID.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_smbsid()
  {
    if(!this.account_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'data')
      return FALSE;
    
    this.accounts[this.account_in_focus].smbsid = _FCT_ANON_ARGS[0];
    return TRUE;
  }


  ## 
  # Sets the GUID(GeneratedUID) for the account in focus.
  #
  # @anon_param [1st:string] GUID.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_guid(overwrite)
  {
    if(!this.account_in_focus || _FCT_ANON_ARGS[0] !~ this.guid_string_pattern)
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].guid) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].guid = _FCT_ANON_ARGS[0];
    return TRUE;
  }
  
  ## 
  # Sets the command shell for the account in focus.
  #
  # @anon_param [1st:string] Command shell path.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
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
  # Sets the account type for the account in focus.
  #
  # @anon_param string Account name.
  #   Whether this is a user or service account is determined by account name,
  #    where service accounts for mac start with an underscore _
  #
  # @return TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_accountType(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;

    if(!isnull(this.accounts[this.account_in_focus].type) && !overwrite)
      return FALSE;

    if (_FCT_ANON_ARGS[0] !~ "^_")
      this.accounts[this.account_in_focus].accountType = 'user';
    else
      this.accounts[this.account_in_focus].accountType = 'service';

    return TRUE;
  }

  ## 
  # Sets password metadata for the account in focus.
  #
  # @anon_param string Password metadata.
  #
  # @return TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_password_metadata(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].password) && !overwrite)
      return FALSE;

    var pw_data = _FCT_ANON_ARGS[0];
    var pw_rgx, pw_create, pw_failcount, pw_failtime, pw_lastset;

    pw_rgx = "<key>creationTime</key>\n.+<real>([\d.]+)</real>";
    pw_create = pregmatch(string:pw_data, pattern:pw_rgx);
    if (!isnull(pw_create))
      this.accounts[this.account_in_focus].password.creationTime = pw_create[1];

    pw_rgx = "<key>failedLoginCount</key>\n.+<integer>([\d]+)</integer>";
    pw_failcount = pregmatch(string:pw_data, pattern:pw_rgx);
    if (!isnull(pw_failcount))
      this.accounts[this.account_in_focus].password.failedLoginCount = int(pw_failcount[1]);

    pw_rgx = "<key>failedLoginTimestamp</key>\n.+>([\d.]+)</";
    pw_failtime = pregmatch(string:pw_data, pattern:pw_rgx);
    if (!isnull(pw_failtime))
      this.accounts[this.account_in_focus].password.failedLoginTimestamp = pw_failtime[1];
    
    pw_rgx = "<key>passwordLastSetTime</key>\n.+<real>([\d.]+)</real>";
    pw_lastset = pregmatch(string:pw_data, pattern:pw_rgx);
    if (!isnull(pw_lastset))
      this.accounts[this.account_in_focus].password.passwordLastSetTime = pw_lastset[1];

    return TRUE;
  }

  ##
  # Set name(username) for the account in focus.
  #
  # @anon_param [1st:string] Account name.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
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
  # Get the name(username) of the account in focus
  #
  # @return Account name or NULL if no account is in focus.
  ##
  public function get_name()
  {
    if(this.account_in_focus)
      return this.accounts[this.account_in_focus].name;
  }

  ## 
  # Search accounts for an account by name and return the guid.
  #
  # @param [name:string] Name of the account.
  #
  # @return [string] GeneratedUID.
  ##
  public function get_account_guid_by_name(name)
  {
    foreach var account(this.accounts)
      if(account.guid && account.name == name)
        return account.guid;
    
    return NULL; 
  }

  ##
  # Set real name(full name) for the account in focus.
  #
  # @anon_param [1st:string] Account real name.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_real_name(overwrite)
  {
    if(!this.account_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].realName) && !overwrite)
      return FALSE;
    
    this.accounts[this.account_in_focus].realName = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Set the focused account's primary group id for the account in focus.
  #
  # @anon_param [1st:integer] Group id.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE on success. FALSE if there was a problem
  ##
  public function set_pgid(overwrite)
  {
    if(!this.account_in_focus ||  typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.accounts[this.account_in_focus].pgid) && !overwrite)
      return FALSE;

    this.accounts[this.account_in_focus].pgid = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Add a group id to the focused account's group membership.
  #
  # @anon_param [1st:string] Group id.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function add_group_membership()
  {
    if(!this.account_in_focus || _FCT_ANON_ARGS[0] !~ this.guid_string_pattern)
      return FALSE;

    foreach var key(accounts[this.account_in_focus].groupMembership)
      if(key == _FCT_ANON_ARGS[0])
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
  # Call report_tag_internal() to save the account data structure to the db.
  #
  # @return NULL
  ##
  public function report()
  {
    if(defined_func("report_tag_internal"))
      report_tag_internal(tag:'identity-mac-accounts:95929:local:tcp', value:this.json_dump());
  }

  ##
  # Initialize the account data structure from a GeneratedUID.
  #
  # @param [guid:data reference] The GeneratedUID to use to initialize the data structure
  #
  # @return The array data structure, or FALSE if an error occurred.
  ##
  private function new_account_from_guid(&guid)
  {
    if(typeof(guid) != 'data')
      return FALSE;
    
    return {
      'guid': guid
    };
  }

  ##
  # Perform a set of validation steps to ensure the account data is 
  # correct.
  #
  # @param [data:array reference] The data to validate
  #
  # @return [boolean] TRUE if the data is valid, FALSE otherwise.
  ##
  private function validate_mac_account_data(&data)
  {
    if(
      typeof(data.uid) == 'int'
    ) return TRUE;
    
    return FALSE;
  }
}
