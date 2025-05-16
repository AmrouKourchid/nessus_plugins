###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# db_instance.inc
#
# Revision: 1.3
###

include("compat_shared.inc");

namespace dbinstance
{
  ##
  # Serializes and encodes a list of database instances
  # Discards any instances missing ip or port
  #
  # @param instances List of arrays that contain instance data
  # for example [{'ip'      : '1.1.1.1',
  #               'port'    : '123',
  #               'data'    : 'c:\user',
  #               'service' : 'orcl'}]
  # @return String the encoded instance data
  ##
  function blob_instances(instances)
  {
    if(empty_or_null(instances)) return NULL;
    #toss out instance if ip and port are not present
    var new_instances = make_list();
    foreach var i (instances)
    {
      if(!empty_or_null(i.ip) && !empty_or_null(i.port))
        append_element(var: new_instances, value: i);
    }
    if(empty_or_null(new_instances)) return NULL;

    new_instances = serialize(new_instances);
    return encode_kb_blob(value:new_instances);
  }

  ##
  # Decodes and deserializes a list of database instances
  #
  # @param blob String the encoded instance data
  # @return List of arrays that contain instance data
  # for example [{'ip'      : '1.1.1.1',
  #               'port'    : '123',
  #               'data'    : 'c:\user',
  #               'service' : 'orcl'}]
  ##
  function deblob_instances(blob)
  {
    if(empty_or_null(blob)) return NULL;
    var instance = decode_kb_blob(value:blob);
    return deserialize(instance);
  }
}
