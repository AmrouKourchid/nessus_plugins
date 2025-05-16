#TRUSTED 85ebc5bf6793430e23e6c4e09f98a2c8999b940d4b85eee6c0bb27cf5b195cc0c6aeb1ceb23f7c4d1cd587a88f51db06d016fd5639c5e2060ec2e1357b0363d84cdaba3fe683cc26f13da8a7ee89e25c2ccecadfed97a35ce2b1d8d07cd90695d3443bed4c0299cdfff7caa9fb257324c46a426586a90bc4e870e83c423ec404d357d397bd08bc29f07d8db3a81d5e29b58ce28734a9f9fa82b90b0dd8372194c8136b6171cf3f7f574c1d94a2dc7d846ed45717f1a833614c1ad4b6c24532d9d81914daa5d2768e90826d6ffeb60b9d5c299987600958901d86df9ae740ba29c987d97d522e6531e98c79dd3813e6dbfbae350f6ca57cd7c31a37661f45d2567ee4ebc34ba5908049cf1d5cab798e52cfc6aca38f53275adeccea981ece6c50de78b2491df88a8c77c4d5f80fac571a30234a8e2092851364d76131a2a0600a352f16b139e13b4a86782b335302a49f2b57da562610a742b1b2beed739e45f6158878bf85abfc23b941ec5bb72e3d5bf30f1b65324edfde689715e91a546c8b8daa2c4088e4246368583fbfb2d02934835fce34d76ad33c89c979ec74547b455178f0473ae6e2a1380ff6c3dbfa8f5509a67a9a3678efc9a4538cece6d0b4ad99afdf7566a13b3417a82ea314524efb4304465c38fdfdcf7a438442c69503e7cf088ab9d358870ddc83adc2cb02c4f0af23c2dfccbf559192894d19deff6949
#TRUST-RSA-SHA256 827e407fd0ae54f804defdf4c878079c00dc36c92e3361d16729e77fc7ecd9c35de0be26e9e356de88d1c8375c0ccc13e539724dc0329ab924348aa77570910f2f465b142c56900c077f1ad9e0fc7c9b09c03acd73c43f275d9fea5f236d9cf88699876a08cfc07164cc470cea880b9708812e4f019850856209c2a12459f4c7659062bddcdc2406ecf67e27ae2e09da102188147e1627475b11ae4c84bc45415be66ed49b4ecbe9d3e770a1c226a58b0b004f72e747667d6ebe4556d9e3244465ce80ffc8ddb4c007d986c86d80ca34a53257927dd0dc30404984b55e19e5e4e50bb0b7359e14105cf3b5731526a6943140985c8a44cf365481fa5302f4810740489e7fd8bcadd2fdc91f1e1d175d29a01fe0317ff9ecba7a249dadbe8f0b820f68c5f05c11fa06188abba104daaa298d13c7e39a368fdcaa60d27120801d7071dd50f8f2e72126b937ac41a323d99454e1f02b3cd30fef9738dfd6fbba9962db3b197043b95e928e7294f09e75510878741079852bbcf609ba8b97a8b990fe9ee4b9664f6318fa23aa14c663a1aa1f89c02c2a380863c3a12a24430645cd370958e1d75bd2ed9018cecdaa2e1ba801d00c6182f858be568ed7546754204949d49267b0f7450b54ce178a4c6bcf6a8e1d804a8c467e74ec59e01238acad990097e7a7c84e43fd6ad3fd389a0a90ddc72a67bff2daadc83ee566ba9b45a70b18
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
# windows_groups_object.inc
#
# Revision: 1.5
###

include('compat_shared.inc');
include('debug.inc');
include('smb_func.inc');
include('json2.inc');

##
# Object representing a Windows group.
##
object windows_groups
{
  var groups = {};
  var unresolved_sids = {};
  ##
  # Some methods require an group key to operate on. This attribute holds the
  # key of the group currently in focus.
  ##
  var group_in_focus = NULL;

  var sid_string_pattern = "^S-\d-\d+(?:-\d+){1,5}$";
  ##
  # Matches "DOMAINNAME/GROUPNAME" patterns
  ##
  var domain_name_pattern = "[^\/\\\[\]:|<>+=;,?*@]+?\/[^\/\\\[\]:|<>+=;,?*@]+?";

  ##
  # Constructor to initialize the windows group data structure.
  #
  # @anonparam [1st:array] Optional. Accepts group data array to initialize the object.
  ##
  function windows_groups()
  {
    if(typeof(_FCT_ANON_ARGS[0]) == 'array')
    {
      var valid = TRUE;
      foreach var group(_FCT_ANON_ARGS[0])
        if(!validate_windows_group_data(data:group))
        {
          valid = FALSE;
          break;
        }

      if(valid)
        this.groups = _FCT_ANON_ARGS[0];
    }
  }

  ##
  # Collect group members whose sid cannot be resolved
  #
  # @param [sids:list] A list of sids which cannot be resolved.
  #
  # @return FALSE if the given list is empty or NULL, NULL otherwise.
  ##
  public function set_unresolved_sids(sids)
  {
    var unresolved_sid;

    if (empty_or_null(sids)) return FALSE;

    foreach unresolved_sid (sids)
    {
      if (isnull(this.unresolved_sids[unresolved_sid]))
        this.unresolved_sids[unresolved_sid]['groupMembership'] = [];

      append_element(var:this.unresolved_sids[unresolved_sid]['groupMembership'], value:this.group_in_focus);
    }
  }

  ##
  # Make a group and add it to the groups data structure. 
  #
  # @param [key:data] String or hex SID.
  #
  # return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function make_group(key)
  {
    var group = NULL;

    if(typeof(this.groups[key]) == 'array')
    {
      this.group_in_focus = NULL;
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Attempted to create a group that already exists using key",
        msg_details: {
          "key": {"lvl": 1, "value": key}});
      return FALSE;
    }

    if(typeof(key) == 'data')
    {
      if(toupper(key) =~ this.sid_string_pattern)
      {
        group = new_group_from_sid_string(sid:key);
      }
      else if(key =~ this.domain_name_pattern)
      {
        group = { 'sid': 'unknown' };
      }
      else
      {
        group = new_group_from_sid_hex(sid:key);
        if(group)
          key = group.sid;
      }
    }
    else
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Invalid data type passed to windows_groups object constructor.");
      return FALSE;
    }

    if(group)
    {
      this.groups[key] = group;
      this.groups[key].accountMembers = [];
      this.groups[key].groupMembers = [];
      this.group_in_focus = key;
      return TRUE;
    }
    else
    {
      this.group_in_focus = NULL;
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Could not create group from provided key",
        msg_details: {
          "key": {"lvl": 1, "value": key}});
    }
    return FALSE;
  }
  
  ##
  # Get the group that is currently in focus.
  #
  # @return Group data as an array, or NULL if no group is in focus.
  ##
  public function get_focused_group()
  {
    if(!this.group_in_focus)
      return NULL;
    
    return this.groups[this.group_in_focus];
  }

  ##
  # Check if a group exists for a given key.
  #
  # @param [key:string] Key value.
  #
  # @return [boolean] TRUE if the group exists, FALSE otherwise.
  ##
  public function group_exists(key)
  {
    if(key && typeof(this.groups[key]) == 'array')
      return TRUE;
    
    return FALSE;
  }

  ##
  # Sets the group that the object will focus operations on.
  #
  # @param [key:string] Key value.
  #
  # @return [boolean] TRUE if successful, FALSE otherwise.
  ##
  public function focus_group(key)
  {
    if(group_exists(key:key))
    {
      this.group_in_focus = key;
      return TRUE;
    }
    
    this.group_in_focus = NULL;
    return FALSE;
  }

  ## 
  # Search groups for a group by name and domain and return
  # the SID if known.
  #
  # @param [name:string] Name of the group.
  # @param [domain:string] Domain name of the group.
  #
  # @return Group SID string, or NULL if no match was found.
  ##
  public function get_group_sid_by_name_domain(name, domain)
  {
    for( var group of this.groups)
      if(group.name == name && group.domainName == domain)
        if(group.sid && group.sid != 'unknown') return group.sid;
    
    return NULL; 
  }

  ##
  # Sets the type of the group. Domain or local.
  #
  # @anonparam [1st:string] Group type. Domain or local.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_group_type(overwrite)
  {
    if(!this.group_in_focus || (_FCT_ANON_ARGS[0] != 'local' && _FCT_ANON_ARGS[0] != 'domain' && _FCT_ANON_ARGS[0] != 'entraid'))
      return FALSE;
    
    if(!isnull(this.groups[this.group_in_focus].type) && !overwrite)
      return FALSE;
    
    this.groups[this.group_in_focus].type = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Sets the domain name that the group belongs to.
  #
  # @anonparam [1st:string] The domain name to set.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_domain_name(overwrite)
  {
    if(!this.group_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.groups[this.group_in_focus].domainName) && !overwrite)
      return FALSE;
    
    this.groups[this.group_in_focus].domainName = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Sets the group name.
  #
  # @anonparam [1st:string] Group name.
  # @param [overwrite:boolean] TRUE to overwrite any existing values. FALSE to prevent overwrites.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function set_name(overwrite)
  {
    if(isnull(_FCT_ANON_ARGS[0]))
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Group name is null');
      return FALSE;
    }
    if(!this.group_in_focus)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Error while trying to set group name ' + _FCT_ANON_ARGS[0] + ': no group in focus');
      return FALSE;
    }
    
    if(!isnull(this.groups[this.group_in_focus].name) && !overwrite)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Overwrite not set to TRUE, aborting',
        msg_details:{'Old name':{lvl:1, value:this.groups[this.group_in_focus].name}, 'New name':{lvl:1, value:_FCT_ANON_ARGS[0]}});
      return FALSE;
    }
    
    this.groups[this.group_in_focus].name = _FCT_ANON_ARGS[0];
    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Successfully set group name',
      msg_details:{'Name':{lvl:2, value:_FCT_ANON_ARGS[0]}, 'Overwrite flag':{lvl:2, value:overwrite}});
    return TRUE;
  }

  ##
  # Get the group name(username).
  #
  # @return [string] Group name
  ##
  public function get_name()
  {
    if(this.group_in_focus)
      return this.groups[this.group_in_focus].name;
  }

  ##
  # Add a account SID to the focused group's membership.
  #
  # @anonparam [1st:string] Account sid.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function add_account_member()
  {
    if(!this.group_in_focus || !this.key_is_valid(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    foreach var sid(this.groups[this.group_in_focus].accountMembers)
      if(sid == _FCT_ANON_ARGS[0])
        return FALSE;

    append_element(var:this.groups[this.group_in_focus].accountMembers, value:_FCT_ANON_ARGS[0]);
    return TRUE;
  }

  ##
  # Add a group SID to the focused group's membership.
  #
  # @anonparam [1st:string] Account sid.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise.
  ##
  public function add_group_member()
  {
    if(!this.group_in_focus || !this.key_is_valid(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    foreach var key(this.groups[this.group_in_focus].groupMembers)
      if(key == _FCT_ANON_ARGS[0])
        return FALSE;

    append_element(var:this.groups[this.group_in_focus].groupMembers, value:_FCT_ANON_ARGS[0]);
    return TRUE;
  }

  ##
  # Dump the group data structure to JSON.
  #
  # @return JSON blob containing the group data.
  ##
  public function json_dump()
  {
    return json_write(this.groups);
  }

  ##
  # Call ``report_tag_internal()`` to save the user data structure to the db.
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
          tag:strcat('identity-windows-groups:', env['plugin_id'], ':local:tcp'),
          value:this.json_dump());
        dbg::detailed_log(lvl:1, msg:'Groups: ' + obj_rep(this.json_dump()));

        if (!empty_or_null(this.unresolved_sids))
        {
          report_tag_internal(
            tag:strcat('identity-windows-unresolveds:', env['plugin_id'], ':local:tcp'),
            value:json_write(this.unresolved_sids));
          dbg::detailed_log(lvl:1, msg:'Unresolved SIDs: ' + obj_rep(this.unresolved_sids));
        }
      }
    }
  }

  ##
  # Initialize the group data structure from a SID string.
  #
  # @param [sid:string reference] The SID of the new account.
  #
  # @return [array] An array containing the given SID.
  ##
  private function new_group_from_sid_string(&sid)
  {
    return {
      'sid': toupper(sid)
    };
  }

  ##
  # Initialize the group data structure from a hex SID.
  #
  # @param [sid:data reference] The SID of the new account.
  #
  # @return An array containing the given SID in string form, or NULL if an error occurred.
  ##
  private function new_group_from_sid_hex(&sid)
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
  # Ensure the provided key is a valid SID or DOMAIN/NAME format.
  #
  # @anonparam [1st:string] The string to validate.
  #
  # @return [boolean] TRUE if the string is a valid key, FALSE otherwise.
  ##
  private function key_is_valid()
  {
    if(
      _FCT_ANON_ARGS[0] =~ this.sid_string_pattern ||
      _FCT_ANON_ARGS[0] =~ this.domain_name_pattern
    ) return TRUE;

    return FALSE;
  }

  ##
  # Perform a set of validation steps to ensure the group data is 
  # correct.
  #
  # @param [data:array reference] The account array to validate.
  #
  # @return [boolean] TRUE if the account data is valid, FALSE otherwise.
  ##
  private function validate_windows_group_data(&data)
  {
    if(
       data.sid =~ sid_string_pattern
    ) return TRUE;

    return FALSE;
  }
}
