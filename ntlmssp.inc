# Revision: 1.3

include("byte_func.inc");
include("compat_shared.inc");
include("debug.inc");
include("lists.inc");

global_var INT = 3;
global_var WIDESTR = 2;
global_var STR = 1;

object ntlm_parser 
{
  var pos, bookmarks;
  var data;
  var p;
  var length;
  var dbg = FALSE;
  var order;

  ##
  # Initialize the ntlm_parser object with data.
  #
  # @anonparam [1st:data] The NTLM data to use in the object.
  #
  # @return [array] The ntlm_parser object.
  ##
  function ntlm_parser () 
  {
    if (isnull(_FCT_ANON_ARGS[0]))
    {
      exit(1, "Error: No data provided to ntlm_parser.");
    } else if (!strlen(_FCT_ANON_ARGS[0])) {
      exit(1, "Error: Data buffer provided to ntlm_parser is empty.");
    }
    this.pos = 0;
    this.bookmarks = [];
    this.data = [_FCT_ANON_ARGS[0]];
    this.length = strlen(this.data[0]);
    this.p = make_array();
    this.order = BYTE_ORDER_LITTLE_ENDIAN;
    if (this.dbg) 
      dbg::detailed_log(
        lvl:2,
        src:FUNCTION_NAME,
        msg:"Bytes of data to parse.",
        msg_details:{
          "Length": {"lvl":2, "value": this.length}});
    return this;
  }

  ##
  # Set the internal debug flag for the object
  #
  # @anonparam [dbg:boolean] The debug flag to enable debugging.
  ##
  public function set_dbg() { this.dbg = _FCT_ANON_ARGS[0]; }

  ##
  # Rewind the parsing position of the object to position 0.
  ##
  public function rewind() { this.pos = 0; }

  ##
  # Bookmark the current position ``pos`` in the ``bookmark`` variable of the object.
  ##
  public function bookmark() 
  {
    collib::push(this.pos, list:this.bookmarks);
  }
  
  ##
  # Set the current parsing position to the last one in the ``bookmark`` variable.
  ##
  public function restore_bookmark()
  {
    if (max_index(this.bookmarks)) this.pos = collib::pop(list:this.bookmarks);
    else if (this.dbg)
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "WARNING: Attempt to restore bookmark, but none remain.");
  }

  ##
  # Get the value associated to the key in the parsed data array of the object.
  #
  # @anonparam [key:string] The key to lookup in the parsed data array.
  #
  # @return The value retrieved from the parsed data array, NULL if an error occurred.
  ##
  public function get() 
  {
    var key = _FCT_ANON_ARGS[0];
    if (isnull(key))
    {
      exit(1, "Error: NULL field passed to .get()");
    }
    var v = this.p[key]; 
    if (isnull(v))
    { 
      if (this.dbg)
        dbg::detailed_log(
          lvl: 2,
          src: FUNCTION_NAME,
          msg: "WARNING: NULL value retrieved with given key",
          msg_details:{
            "Key": {"lvl":2, "value": key}});
      v = 'unknown';
    }
    return v;
  }

  ##
  # Add an entry to the parsed data array of the object.
  #
  # @anonparam [key:string] The key to lookup in the parsed data array.
  # @anonparam [value:any] The value to give for the ``key`` in the array.
  #
  # @return NULL always
  ##
  public function set() 
  {
    var key = _FCT_ANON_ARGS[0];
    var value = _FCT_ANON_ARGS[1];
    if (isnull(key))
    { 
      exit(1, "Error: Attempt to set NULL field with .set()");
    } 
    if (isnull(value))
    {
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "WARNING: attempt to set value of the key to NULL",
        msg_details: {
          "Key": {"lvl": 1, "value": key}});
      return NULL;
    }
    this.p[key] = value; 
    return NULL;
  }
  
  ##
  # Add data to the list of data to parse.
  #
  # @remark This function rewinds the parsing position with ``rewind()``.
  #         And it also bookmarks the current position with ``bookmark()``.
  #
  # @anonparam [1st:data] The data to add to the object.
  ##
  function push_data ()
  {
    collib::push(_FCT_ANON_ARGS[0], list:this.data);
    this.bookmark();
    this.rewind();
    this.length = strlen(_FCT_ANON_ARGS[0]);
    return NULL;
  }

  ##
  # Remove the last data entry in the list of data to parse.
  #
  # @remark This function restores the position to the last bookmark.
  #
  # @return The data that was removed from the data array.
  ##
  function pop_data ()
  {
    var ret;
    this.restore_bookmark();
    ret = collib::pop(list:this.data);
    this.length = strlen(this.data[max_index(this.data)-1]);
    return ret;
  }

  ##
  # Parse the last entry in the data to parse list.
  #
  # @param [field:string] The key of the parsed data array in which the parsed data will be stored.
  # @param [len:integer] The length of data to parse.
  # @param [type:integer] The type of data expected.
  #
  # @return The data parsed, NULL if an error occurred.
  #
  # @remark The function also stores the parsed data in the parsed data array with the key ``field``,
  #         or under "TEMPORARY VALUE" if ``field`` is NULL.
  ##
  function parse_field (field, len, type)
  {
    var val, chunk, data = this.data[max_index(this.data)-1];

    if (this.pos + len > this.length)
    {
      dbg::detailed_log(
        lvl:1,
        src:FUNCTION_NAME,
        msg:"WARNING: Tried to parse past length of data.",
        msg_details:{
          "this.pos":{"lvl":2, "value":this.pos},
          "this.length":{"lvl":2, "value":this.length},
          "len":{"lvl":2, "value":len}});
      return NULL;
    }
    chunk = substr(data, this.pos, this.pos + (len - 1));
    this.pos += len;

    if (type == INT && len <= 4)
    { 
      if (len == 1) val = getbyte(blob:chunk, pos:0);
      else if (len == 2) val = getword(blob:chunk, order:this.order, pos:0);
      else if (len == 4) val = getdword(blob:chunk, order:this.order, pos:0);
    } else if (type == WIDESTR) {
      var i, str = '';
      for (i = 0; i < len-1; i += 2) str += chunk[i];
      val = str;
    } else {                   # when type is STR (raw)
      val = chunk;
    }

    if (!isnull(val) && !isnull(field)) this.set(field, val);
    
    if (isnull(field)) field = "TEMPORARY VALUE";
    if (this.dbg)
      dbg::detailed_log(
        lvl:3,
        src:FUNCTION_NAME,
        msg:"Parsed data in the given field",
        msg_details:{
          "this.pos":{"lvl":3, "value":this.pos},
          "field":{"lvl":3, "value":field},
          "Field value":{"lvl":3, "value":hexstr(chunk)},
          "Data":{"lvl":3, "value":val}});

    return val;
  } 

  ##
  # Parse all of the data given when initializing the object.
  #
  # @return [array] The array containing all of the parsed data.
  ##
  public function parse()
  {
    this.rewind();
    this.parse_field(len:8, type:STR, field:"identifier");
    this.parse_field(len:4, type:INT, field:"message_type");
    this.parse_field(len:2, type:INT, field:"domain_length");
    this.parse_field(len:2, type:INT, field:"domain_max");
    this.parse_field(len:4, type:INT, field:"domain_offset");
    this.parse_field(len:4, type:INT, field:"server_flags");
    this.parse_field(len:8, type:STR, field:"challenge");
    
    # now, we step ahead to the domain name
    this.bookmark();
    this.pos = this.get("domain_offset");
    this.parse_field(len:this.get("domain_length"), type:WIDESTR, field:"target_realm");
    var post_domain = this.pos;
    this.restore_bookmark();

    this.parse_field(len:8, type:STR, field:"context");
    this.parse_field(len:2, type:INT, field:"target_info_length");
    this.parse_field(len:2, type:INT, field:"target_info_max");
    this.parse_field(len:4, type:INT, field:"target_info_offset");

    if (this.get("target_info_offset") >= this.pos + 7 &&
        this.get("domain_offset") >= this.pos + 7)
    {
      this.parse_field(len:1, type:INT, field:"os_major_version");
      this.parse_field(len:1, type:INT, field:"os_minor_version");
      this.parse_field(len:2, type:INT, field:"os_build");
      this.parse_field(len:4, type:STR, field:"reserved");
      if (this.get("reserved") != '\x00\x00\x00\x0f') 
      {
        var k;
        foreach (k in ["os_major_version", "os_minor_version", "os_build"])
          this.set(k, "unknown format ("+this.get(k)+"?)");
      } else {
        this.set("os_version", this.get("os_major_version") + '.' 
                             + this.get("os_minor_version") + '.'
                             + this.get("os_build"));
      }
    }

    if (this.get("target_info_length") > 0)
    {
      var old_len, av_names;
      this.pos = post_domain; #??
      this.parse_field(len:this.get("target_info_length"), type:STR, field:"target_info");

      # From here on, we're just parsing the target_info blob
      this.push_data(this.get("target_info"));
      av_names = {0x00: ["EOL", 0],
                  0x01: ["netbios_computer_name", WIDESTR],
                  0x02: ["netbios_domain_name", WIDESTR],
                  0x03: ["dns_computer_name", WIDESTR],
                  0x04: ["dns_domain_name", WIDESTR],
                  0x05: ["dns_tree_name", WIDESTR],
                  0x06: ["av_flags", INT],
                  0x07: ["timestamp", INT],
                  0x08: ["restrictions", STR],
                  0x09: ["target_name", STR],
                  0x0A: ["channel_bindings", STR]};
      
      var type, av_id_type, av_id, av_id_h, av_len = 0;
      while (this.pos < this.length) 
      {
        av_id  = this.parse_field(len:2, type:INT);
        av_len = this.parse_field(len:2, type:INT);
        if (isnull(av_id)) 
        {
          if (this.dbg)
            dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "WARNING: failed to parse av_id.");
          this.pos += av_len;
          continue;
        }
        av_id_type = av_names[av_id];
        if (isnull(av_id_type))
        {
          if (this.dbg)
            dbg::detailed_log(
              lvl: 2,
              src: FUNCTION_NAME,
              msg: "WARNING: did not recognize av_id",
              msg_details:{
                "av_id":{"lvl":2, "value":int2hex(av_id)}});
          this.pos += av_len;
          continue;
        }
        av_id_h = av_id_type[0];
        type = av_id_type[1];
  
        if (this.dbg)
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "Values gathered",
            msg_details:{
              "av_id_h":{"lvl":3, "value":av_id_h},
              "av_len":{"lvl":3, "value":av_len},
              "av_type":{"lvl":3, "value":type}});

        if (av_id_h == "EOL") break;
        
        this.parse_field(len:av_len, type:type, field:av_id_h);
      }
      this.pop_data();
    } 
    return this.p;
  } 
}
