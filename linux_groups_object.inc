#TRUSTED 3a78739c783d3d976598bf47ca5f143a09a5456f289eb2737df812d2021f3bf9b1710c20e41ca4b607c6d3803f3e49642e08ebf2c4c66853d550c4d471f9a57470eb9ddb8e9291aad3c222221bca8920a00a5771c1853c9c47c56df29a32d98ce7f6f70d44e019eaf62cef1a5df06ba7c43d1d2fce877e6219fa49dab363271edcc96d9e61115fa61b974e516ead2640961d64daad9813db64f4a39e663f73a6912e332f62c051d68301f4ea84679afad3bb723be6ec92928f6c40e096cde34d3b4df17544a4c73c310a7def30fe141dcbfd5d408b76fbdb853eed1f8643a0c99b6a87cea08a31dc153af23c8deccb4b9810a43d8ee5e3b15b20a2529079053ff8806c68ce312c2d4e5f985daa2e33892d9bda7c4716f6510d33458b773770c7b5036559dbfbbcb6dae76b088ba7152486b185810b380c033fef9c4d383a7581f5b88f4e4034c0906e30614bf7fdd8258f40568ce6305c3636a96f9910709c037d36c592def2f4e34c0268f660c470f30ed77b71ed2ea12948b598483e7e158720e7612500e6ab26c0ce557cd7b3e920a09abd84b310b7144cd1f1c7ceda6447ebc881b2061a748da2a048a166bc9646520170f737341819527d7efff56496aecb3e57b83d17bd8d1a7655a50b485b73175a68edc40ba6e1d14d1111dfe5caf3008f4a6d520d8745bc1b7d8e6e73c21b51fe2aa460f9409081cea798132f24d0
#TRUST-RSA-SHA256 7075045d6b9a5bf609f06f5508f3eff13c09fb7f7ee3e87e4a460c45afa0f70b182927027cb92f7f57cf14f3d5f41c71715e25b43c335d2b1826ad0dcd9b094941e0e4d87fc80d55844e2df94815608b9f84dfc39c184bb4e00ac8e83c6ba752cfe7e754a202fddff377dda12bdf7f116543f13f04cbd7691b3b3bbe7197b5f861a874df1a426f93c374bd065c52300a612d7cd52e9ae028f6d1b818c29da4b7d9bf8f8de382a6853ae0b9d3bb733e3ec643867fb7fffc9a36c80988699722dea73e8b1cff09b77be04c8f92fe1dd5d14af186929850602a8a16d88aa9dd945942b9d31ad60bb68658368b858bb5226bc2f034cdea0d4d903511c8c4a96870d258c3fc84fb555013180e73172d3d26a000eb4a6b1c17af4e6ad6c81984b4b15765c5af33b839f4294b544aa37051c3c65e12487a705badeabb46f89c8fdb6b0307be3afe2569df65638d0f788d7022f41cf0dd73d61931440bf9f7d725e04b94a18a3c71cc7b2a18989b94b98412419bcd15a8a08399a9828ed27b0d9f1115faf6fed6ac7b5af6f23e7af70899506d5f43f9431b3223e8c0dbf4d20a56ab7dee3bd9da7573611fa6e05e96cae418a4ec2b697d16bf889c12bba4b79f6eaa90410868af2678e48706a3ac9cf698eca10fa5838dd6648e42ce1fd6df3ae6025ce29aac6fba0ebebd300713b7456c2a0219afe9d074b083a3b8f846fc08e1257f7b
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
# linux_groups_object.inc
#
# Revision: 1.3
###
include('debug.inc');
include('json2.inc');

##
# Object representing Linux user groups.
##
object linux_groups
{
  var groups = {};
  ##
  # Some methods require a group key to operate on. This attribute holds the
  # key of the group currently in focus.
  ##
  var group_in_focus = NULL;

  ##
  # Make a group and add it to the groups data structure. 
  #
  # @param [key:integer] Group id(gid).
  #
  # @return [boolean] TRUE if the data structure was successfully created, FALSE otherwise.
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

    if(typeof(key) == 'int')
    {
      group = new_group_from_gid(gid:key);
    }
    else
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Invalid data type passed to linux_groups object constructor.");
      return FALSE;
    }

    if(group)
    {
      this.groups[key] = group;
      this.groups[key].groupMembership = [];
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
  # @return [array] Group data.
  ##
  public function get_focused_group()
  {
    if(!this.group_in_focus)
      return NULL;
    
    return this.groups[this.group_in_focus];
  }

  ##
  # Check if a group exists for a given gid.
  #
  # @param [gid:string] string gid value.
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
  # @param [sid:string] string SID value.
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
  # Search groups for a group by name and return the gid.
  #
  # @param [name:string] Name of the group.
  #
  # @return [string] Group id(gid).
  ##
  public function get_gid_by_name(name)
  {
    foreach var group(this.groups)
      if(group.gid && group.name == name)
        return group.gid;
    
    return NULL; 
  }

  ##
  # Sets the group name.
  #
  # @anon_param [1st:string] Group name.
  # @param [overwrite:boolean] Boolean to set to TRUE to overwrite the group name if it already exists.
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
  # Get the group name
  #
  # @return Group name
  ##
  public function get_name()
  {
    if(this.group_in_focus)
      return this.groups[this.group_in_focus].name;
  }

  ##
  # Add a uid to the focused group's membership.
  #
  # @anon_param [1st:integer] Account uid.
  #
  # @return [boolean] TRUE if the operation was successful, FALSE otherwise
  ##
  public function add_group_membership()
  {
    if(!this.group_in_focus || typeof(_FCT_ANON_ARGS[0]) != 'int')
      return FALSE;
    
    foreach var key(this.groups[this.group_in_focus].groupMembership)
      if(key == _FCT_ANON_ARGS[0])
        return FALSE;
    
    append_element(var:this.groups[this.group_in_focus].groupMembership, value:_FCT_ANON_ARGS[0]);
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
  # Call report_tag_internal() to save the group data structure to the db.
  #
  # @return NULL
  ##
  public function report()
  {
    if(defined_func("report_tag_internal"))
      report_tag_internal(tag:'identity-linux-groups:95928:local:tcp', value:this.json_dump());
  }

  ##
  # Initialize the group data structure from a SID string.
  #
  # @param [gid:string reference] The SID to use to initialize the group data
  #
  # @return An array containing the SID, FALSE if an error occurred.
  ##
  private function new_group_from_gid(&gid)
  {
    if(typeof(gid) != 'int')
      return FALSE;
    
    return {
      'gid': gid
    };
  }

  ##
  # Perform a set of validation steps to ensure the group data is 
  # correct.
  #
  # @param [data:array reference] The data structure to validate
  #
  # @return [boolean] TRUE if the data is valid, FALSE otherwise.
  ##
  private function validate_linux_group_data(&data)
  {
    if(typeof(data.gid) == 'int') 
      return TRUE;
    
    return FALSE;
  }
}
