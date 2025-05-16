include('compat_shared.inc');
include('lists.inc');

object manifest_file_parser
{
  ##
  # Data structure that stores the results of parsing. This is the only
  # property intended for public access.ff
  ##
  var section_data = [];

  var pos = 0; # Tracks the current character that is being parsed.
  var section = 0;  # Tracks the section currently being parsed.
  var file_contents;
  var file_len;
  var line;
  var additional_attributes;
  # Default attributes to save from the main section
  var MAIN_ATTRIBUTES = [
    'Manifest-Version',
    'Created-By',
    'Class-Path',
    'Main-Class',
    'Ant-Version',
    'Implementation-Title',
    'Implementation-Version',
    'Implementation-Vendor',
    'Specification-Title',
    'Specification-Version',
    'Specification-Vendor'
  ];
  # Default attributes to save from each individual section
  var PERENTRY_ATTRIBUTES = [
    'Name',
    'Implementation-Title',
    'Implementation-Version',
    'Implementation-Vendor',
    'Specification-Title',
    'Specification-Version',
    'Specification-Vendor'
  ];

  ##
  # Gather args and start parsing.
  #
  # @anonparam Full contents of the manifest file.
  # @anonparam Additional attribute values to save in the form of the header
  #                   names in a list. (e.g. ['Bundle-Name', 'Import-Package'])
  ##
  function manifest_file_parser()
  {
    this.file_contents = _FCT_ANON_ARGS[0];
    this.file_len = len(this.file_contents);

    if(typeof_ex(_FCT_ANON_ARGS[1]) == 'list')
      this.additional_attributes = _FCT_ANON_ARGS[1];

    while(this.file_len > this.pos)
      parse_section();
  }

  ##
  # Parse a manifest section. Ends and the next empty line.
  ##
  function parse_section()
  {
    get_next_line();

    append_element(var:this.section_data, value:{});

    while(this.line != '\n' && this.line != NULL)
    {
      parse_attribute();
      get_next_line();
    }
    
    if(!empty_or_null(this.section_data[this.section]))
      this.section += 1;
  }

  ##
  # Parse the attribute at the current line
  ##
  function parse_attribute()
  {
    var attribute = get_attribute_with_continuations_as_single_line();
    var colon_pos = stridx(attribute, ':');
    var header = substr(attribute, 0, colon_pos - 1);

    if(should_save_attribute(header:header))
      this.section_data[this.section][header] = substr(attribute, colon_pos + 2, len(attribute));
  }

  ##
  # Attributes can have continuation lines that start with a SPACE per the
  # specification. Check for continuation lines by peeking ahead and then
  # consuming the next line if it starts with a SPACE.
  ##
  function get_attribute_with_continuations_as_single_line()
  {
    var attribute = substr(this.line, 0, len(this.line) - 2);

    while(this.pos < this.file_len && this.file_contents[this.pos] == ' ')
    {
      get_next_line();
      attribute += substr(this.line, 1, len(this.line) - 2);
    }

    return attribute;
  }

  ##
  # Perform a check to see if the current attribute should be saved
  # to the final data structure.
  #
  # Section 0 is the main section
  # Section 1..1+n are indivdual entries
  ##
  function should_save_attribute(&header)
  {
    var item;
    if(this.section == 0)
    {
      foreach item(this.MAIN_ATTRIBUTES)
        if(item == header) return TRUE;
    }
    else
    {
      foreach item(this.PERENTRY_ATTRIBUTES)
        if(item == header) return TRUE;
    }

    foreach item(this.additional_attributes)
      if(item == header) return TRUE;
    
    return FALSE;
  }

  ##
  # Get the next line from the manifest file. This is 8-10x faster than split() and uses
  # no additional memory.
  ##
  function get_next_line()
  {
    if(this.pos > this.file_len) return NULL;

    var line = '', i;
    for(i=this.pos;this.file_len > i; i++)
      if(is_newline(pos:i))
      {
        line += '\n';
        break;
      }
      else
      {
        line += this.file_contents[i];
      }
    this.pos += len(line);
    this.line = line;
  }

  ##
  # The Manifest specification allows for three newline styles.
  # CR LF | LF | CR (not followed by LF)
  #
  # Note: If CR LF is used, this.pos must be advanced by one.
  ##
  function is_newline(pos){
    if(this.file_contents[pos] == '\n') return TRUE;
    
    if(
      (pos + 1) < this.file_len && 
      this.file_contents[pos] + this.file_contents[pos + 1] == '\r\n'
    ) 
    {
      this.pos += 1;
      return TRUE;
    }

    if(this.file_contents[pos] == '\r') return TRUE;
    
    return FALSE;
  }
}
