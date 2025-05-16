#TRUSTED 2a77d430f12ab9dfef64ff9fcefa9dac10762a68342d813de82c4a1d19b9032f8b357356fcfc550d1ac15bcd4c718753819e5294ee2e129be01a0375abd8121beae827cb852e769eb56d4278d1fb9da1f86da34ef276216cf8097b3e320a6240f8e4596d0138ad2ca2b41e0a5a917e8e96cf89f39eabfcdf6b990290a363447395469de041fc99d45b9eaeb665c61680a9d4a09a1bad2c5f7190f9f83c8aa0c512261860af6cc696156bf89995d5aecde9f56d03a12c83c70f5732c1f3c806a6d51dec6b72078ef5da57d064cc3f352f774be49396f7b274642ebf8cd69e5fe2a081970bce6dd410245d15f993d18e562cfa1fd065f0e48e93c39f775ec8ba053be9b23dacb058821fa7b386a78489bae08691dcac14b7dd0e47e885c269f5de006499093d86a0a098137203ff14281fe0080b841e9fc7eaf7c40235f0b63c652e2350bf4f2ec947620ce6dcb22bc26be02e93d8e922bfeae8a0dacfae636320b77806e8ae08bccad35fa524d6e910408b6d02a78e91cf321a2d46e69063144a9f8df43887fed4a4d436cf5daaf8076f683330f9f6677e588469d95613c03a2ce2d28103e96f7421f7f458ed2a8b62a98b64050a3eb1c42970c9ef27458f69d75d344b9c65b328665f6e3e25ad9130211fe7554079b16438d4a89fc43cc845c75bbdc4661a434303707d7fb31b1d1a6f2fc3084da005a73c2f0877e194aa23a3
#TRUST-RSA-SHA256 1e61865fc49cee34c135c3515cb63ec13586fca15a9c97757204bccfd650ed9c59a45aa762c21b53200278762fd0dc24bae2da50ce7ca9cffbd476f59d173641b6ea0ac218881e3fa2adfac98fc64c3c69a4aa32b1f094d4b0ec7feb4a147fa25d71443e9eb01097fb024dc122ecf6669548ed963953702991f8a1d4b4e5b0bdcc6b1e56f012abb069de78bf79eb5022b156c4313295a299cb152663e8dbf5afd064f98e226608c505c03127e498a469dc601b20f6e150163f5a99c136d2b5a942421f952a6cc2aa59a739734e8066d000f2c67ac704e49efec07b240a321e21adc726eca7347b53a2fd55c50b3bddf3fe52a6a88dfb66c24838a34f8c447e74b75ba61c000c6c12cc0fef7f115bd41d6093f0485b327564d246b2dacb0e03e2143ebe9e76c6e2730ddd2029179bf7bf00c5f7c3a0d887a772c1a8f0ff89b1f78fa1c01c7348c6945fee9455cc98de2e126ebef2a722feb2a96ef50e5f40850f0acd810dd1c1da94976f87ca493738537d477268d6a37052dc2bb87e2da30272cb408f9404464b8eefccc83393306207c9da8e96c10b1fd4c8e31992f252dbc9c51542e226abcee0cb86cbbc748f3f1c9aab129b92e3578f2ee7b89831e4eb230a7a070fe7463e0fb48b665d0af7d575183273fadb8a4844521db62474537eb5be50b4aa84204ae28f07a6a20c234e90576c74340b63fc9ab586323fedb92ee4
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
# mac_group_object.inc
#
# Revision: 1.4
###
include('debug.inc');
include('json2.inc');

##
# Object representing Mac user groups.
##
object mac_groups
{
  var groups = {};
  ##
  # Some methods require an group key to operate on. This attribute holds the
  # key of the group currently in focus.
  ##
  var group_in_focus = NULL;

  var guid_string_pattern = "^[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}$";

  ##
  # Make a group and add it to the groups data structure. 
  #
  # @param [key:string] GenerateUID(guid).
  #
  # @return [boolean] TRUE if teh group was added to the data structure, FALSE otherwise
  ##
  public function make_group(key)
  {
    var group;
    this.group_in_focus = NULL;

    if(key =~ this.guid_string_pattern)
    {
      group = new_group_from_guid(guid:key);
    }
    else
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Invalid data type passed to make_group.");
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
  # @return [array] Group data.
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
  # @return NULL.
  ##
  public function focus_group(key)
  {
    if(this.group_exists(key:key))
      this.group_in_focus = key;
    else
      this.group_in_focus = NULL;
  }

  ##
  # Sets the scope for the group in focus. Domain or local.
  #
  # @anon_param [1st:string] Group scope. Domain or local.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_group_scope(overwrite)
  {
    if(!this.group_in_focus || (_FCT_ANON_ARGS[0] != 'local' && _FCT_ANON_ARGS[0] != 'domain'))
      return FALSE;

    if(!isnull(this.groups[this.group_in_focus].scope) && !overwrite)
      return FALSE;

    this.groups[this.group_in_focus].scope = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ## 
  # Search groups for a group by primary group id and return the guid(GeneratedUID).
  #
  # @anon_param [1st:integer] Primary id of the group.
  #
  # @return [string] guid(GeneratedUID).
  ##
  public function get_group_guid_by_pgid()
  {
    foreach var group(this.groups)
      if(group.guid && group.pgid == _FCT_ANON_ARGS[0])
        return group.guid;
    
    return NULL; 
  }

  ## 
  # Search groups for a group by name and return the guid(GeneratedUID).
  #
  # @anonparam [1st:string] Name of the group.
  #
  # @return [string] guid(GeneratedUID).
  ##
  public function get_group_guid_by_name()
  {
    foreach var group(this.groups)
      if(group.guid && group.name == _FCT_ANON_ARGS[0])
        return group.guid;
    
    return NULL; 
  }

  ##
  # Set the name for the group in focus.
  #
  # @anon_param [1st:string] Group name.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_name(overwrite)
  {
    if(!this.group_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.groups[this.group_in_focus].name) && !overwrite)
      return FALSE;
    
    this.groups[this.group_in_focus].name = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Get the name of the group in focus
  #
  # @return [string] Group name
  ##
  public function get_name()
  {
    if(this.group_in_focus)
      return this.groups[this.group_in_focus].name;
  }

  ##
  # Set the real name(full display name) for the group in focus.
  #
  # @anon_param [1st:string] Group real name.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_real_name(overwrite)
  {
    if(!this.group_in_focus || isnull(_FCT_ANON_ARGS[0]))
      return FALSE;
    
    if(!isnull(this.groups[this.group_in_focus].realName) && !overwrite)
      return FALSE;
    
    this.groups[this.group_in_focus].realName = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ## 
  # Set the unique group id for the group in focus.
  #
  # @anon_param [1st:integer] Primary group id.
  # @param [overwrite:boolean] Boolean set to TRUE to overwrite the value if it already exists. (optional)
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_pgid(overwrite)
  {
    if(!this.group_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    if(!isnull(this.groups[this.group_in_focus].pgid) && !overwrite)
      return FALSE;

    this.groups[this.group_in_focus].pgid = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ## 
  # Set the SMBSID for the group in focus.
  #
  # @anon_param [1st:integer] The SMBSID.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function set_smbsid()
  {
    if(!this.group_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'data')
      return FALSE;
    
    this.groups[this.group_in_focus].smbsid = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  ##
  # Add an account GeneratedUID(guid) to the focused group's membership.
  #
  # @anon_param [1st:string] Account GeneratedUID(guid).
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function add_account_member()
  {
    if(!this.group_in_focus || _FCT_ANON_ARGS[0] !~ this.guid_string_pattern)
      return FALSE;
    
    foreach var key(this.groups[this.group_in_focus].accountMembers)
      if(key == _FCT_ANON_ARGS[0])
        return FALSE;
    
    append_element(var:this.groups[this.group_in_focus].accountMembers, value:_FCT_ANON_ARGS[0]);
    return TRUE;
  }

    ##
  # Add a group GeneratedUID(guid) to the focused group's membership.
  #
  # @anon_param [1st:string] Group GeneratedUID(guid).
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function add_group_member()
  {
    if(!this.group_in_focus || _FCT_ANON_ARGS[0] !~ this.guid_string_pattern)
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
  # Call report_tag_internal() to save the user data structure to the db.
  #
  # @return NULL
  ##
  public function report()
  {
    if(defined_func("report_tag_internal"))
      report_tag_internal(tag:'identity-mac-groups:95929:local:tcp', value:this.json_dump());
  }

  ##
  # Initialize the group data structure from a GUID string.
  #
  # @param [guid:data reference] The GUID to use to initialize the data structure.
  #
  # @return The array data structure, or FALSE if an error occurred.
  ##
  private function new_group_from_guid(&guid)
  {
    if(typeof(guid) != 'data')
      return FALSE;
    
    return {
      'guid': guid
    };
  }

  ##
  # Perform a set of validation steps to ensure the group data is correct.
  #
  # @param [data:array reference] The data to validate.
  #
  # @return [boolean] TRUE if the data is valid, FALSE otherwise.
  ##
  private function validate_mac_group_data(&data)
  {
    if(data.guid =~ this.guid_string_pattern) 
      return TRUE;
    
    return FALSE;
  }
}
