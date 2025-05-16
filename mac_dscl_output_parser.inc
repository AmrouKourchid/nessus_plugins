#TRUSTED 6eca185742c6d908cb3d70317853d847e4a54face7ef3b007da7bb3a98fc7720759d39208a565627274a3cf02a5251c73d7aa2b42503f95137f4960ca34831cb0e636e088d1feb89578ed3578f0cc4149fde8856a881cc95ca1626a6176550fc8b82ce452f32999bae6077883db1387cae6f3c8fb3620d5ec1e48688da29f7d327491784775094d8344d395465575964e885befa1584c9def2a57d49fffe391f85f490a58f64fc60d3b01b8879e5545ce4d742e23e1509125e458d848352f8ac1b77cc003c9685a1953f67d2f1530b1f8d81bbda89f8ce5953ba93f6fcb58d1a85f0cbb1372506f94809a3b7cbab75570a275746f1cb27e0ac6d53e14f3afb4ac1b284c03c118e16bd3bc87c963e40b8d017fe24bf9f186410ce3479bdf31c0f302ed5a42dca6fffe11ea3d83d241d6278521b4d781cafbc4d81fefcd6e229c7f036e475336fb6844738d3c2d593886681b9d902a9dc16b30b69f7935205f31451db6b3ce50cd5052e2292fd7a042d807404d5722e2cc9bb61870cbb177020dd654542c8efa0a8d7c4bd3a4938f425bc2e257291cb4cbf9c74367a9bf61a20fe62b48e95f83906ecc128ff13d754835ee7faf9cda2396d700d5602d53eb211ad231b9e5d971dda15f6e176195f1a1fbbbb322759384192398ac904c8aab5449c6162eff69aae09fd0838f454f9f5af9cab30d1df0882d160c97093ff11011f68
#TRUST-RSA-SHA256 27f596240d9dbfd35e4e54c11780879b90f4511d60065fa116d654b90f608d0698033a0096de3ce6b2071e203799e145a1ab127defd1a6aafc3edd3351564172c3564e7b007f0cdfbfc828d35bfa4ccb26b4ff81d7d289678ddd7abb8cdaeae4137be31a6d63685f383d796fe0a2d612fa55890e404489e8fa694570b43447e8a946eaab6a73376c7694c5ff6c0db47aff85ef08d3481c7dbdb4793eef4991b67145d3b31b921d10804b3fa28a4665b7cb8da1a23842249269847c7cd984ca265c2c89262e32124979e5a69fcb06679ffdef77369aba8ab45c2eaa454d5bcb2f31ccd73f820d5c72c89d15d12ae340d000580277ad233013d1206ab61f97420f31de175158f5570e5a78ac7c87933560a78d592319e46714680948a7ddf6e0cca495c178a9185ffa3f00a17c9807f8d0e81790712644979fa3ec55a62bbf0aac7ce7c2f03ce1d33744f656303eb65cf265ee29fd7910db9952a4492cc3611c8b3ffd244f200ad03c0955eb7b89c9a732332a5855062db8b7c83885096bda645cf723fe7895c3bca05e6d3b309dbf82d951e1048f39fd5bca0b7b1bb365fcd7d4618f23d1b5a54b07ffa394932a3959a32aa93f153dca32d7e30f81007b5a4dff7b8f3dba6c04bef82c000aeebd23173df824ef21afcd319469f6a6fbd2f226a90710d3d48c85fe83961b16c980626ac3c5f4750bd88ac7176657a181fe9bf46d
##
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
# Revision: 1.1
## 
include('compat_shared.inc');

object mac_dscl_output_parser
{
  ##
  # Data structure that stores the results of parsing. This is the only
  # property intended for public access.
  ##
  var dscl_obj_data = [];

  var pos = 0; # Tracks the current character that is being parsed.
  var dscl_obj = 0;  # Tracks the section currently being parsed.
  var output_contents;
  var output_len;
  var line;

  ##
  # Gather args and start parsing.
  #
  # @anonparam Full contents of the manifest file.
  # @anonparam Additional attribute values to save in the form of the header
  #                   names in a list. (e.g. ['Bundle-Name', 'Import-Package'])
  ##
  function mac_dscl_output_parser()
  {
    this.output_contents = _FCT_ANON_ARGS[0];
    this.output_len = len(this.output_contents);

    while(this.output_len > this.pos)
      parse_dscl_obj();
  }

  ##
  # Parse a dscl output section. Ends and the next line containing only a dash.
  ##
  function parse_dscl_obj()
  {
    get_next_line();

    append_element(var:this.dscl_obj_data, value:{});

    while(this.line != '-\n' && this.line != NULL)
    {
      parse_attribute();
      get_next_line();
    }
    
    if(!empty_or_null(this.dscl_obj_data[this.dscl_obj]))
      this.dscl_obj += 1;
  }

  ##
  # Parse the attribute at the current line
  ##
  function parse_attribute()
  {
    var colon_pos = stridx(this.line, ':');
    var attr_name = substr(this.line, 0, colon_pos - 1);
    if('dsAttrType' >< attr_name)
    {
      this.line = substr(this.line, colon_pos + 1, len(this.line));
      colon_pos = stridx(this.line, ':');
      attr_name = substr(this.line, 0, colon_pos - 1);
    }
    
    var attr_value = substr(this.line, colon_pos + 2, len(this.line));
    if(attr_value) 
      this.dscl_obj_data[this.dscl_obj][attr_name] = split(chomp(attr_value), sep:' ', keep:FALSE);
    else
      this.dscl_obj_data[this.dscl_obj][attr_name] = get_attr_values_from_space_leading_lines();
  }

  function get_attr_values_from_space_leading_lines()
  {
    var attr_values = [];
    while(this.pos < this.output_len && this.output_contents[this.pos] == ' ')
    {
      get_next_line();
      if(substr(this.line, 0, 5) == ' <?xml')
        append_element(var:attr_values, value: get_plist_xml_data_as_attribute());
      else
        append_element(var:attr_values, value: chomp(trim(this.line)));
    }
    return attr_values;
  }
  
  function get_plist_xml_data_as_attribute()
  {
    var data = this.line;
    while(this.pos < this.output_len && this.line != '\n')
    {
      get_next_line();
      data += this.line;
    }
    return data;
  }

  ##
  # Get the next line. This is 8-10x faster than split() and uses
  # no additional memory.
  ##
  function get_next_line()
  {
    if(this.pos > this.output_len) return NULL;

    var line = '', i;
    for(i=this.pos;this.output_len > i; i++)
      if(this.output_contents[i] == '\n')
      {
        line += '\n';
        break;
      }
      else
      {
        line += this.output_contents[i];
      }
    this.pos += len(line);
    this.line = line;
  }
}
