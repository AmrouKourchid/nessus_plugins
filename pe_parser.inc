###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# pe_parse.inc
# Revision: 1.4
###

include("compat_shared.inc");
include("byte_func.inc");
include("debug.inc");
include("dump.inc");
include("charset_func.inc");
include("smb_func.inc");

# dump.inc is used for debugging purposes
# include("dump.inc");


##
# An objact that can be used to parse 
# a PE file format
##
object pe_parser{

  # bitmask table to handle debugging
  var DEBUG;
  var last_error;
  var last_error_cnt;

  ##
  # pe_parse constructor
  #
  # @anonparam [1st:integer] bitmask to handle debug msg printing
  #   0x01 = dbg_print display enabled
  #   0x02 = dbg_print table enabled
  #   0x04 = spad_log enabled
  ##
  function pe_parser()
  {
    this.DEBUG = _FCT_ANON_ARGS[0];
    
    # Use this to report spad_log debugging info
    if (this.DEBUG & 0x04)
    {
      replace_kb_item(name:"global_settings/enable_plugin_debugging", value:1);
    }

    this.last_error = make_array();
    this.last_error_cnt = 0;
  }

  ##
  # Set last_error, This should be used to manage failures
  # so we can bubble them up to the calling function
  #
  # @param [msg:string] the error message
  # @param [audit:integer] audit code if used, null if not an audit
  # @param [sev:integer] 0 is passive, 1 is critical
  #
  # @return NULL;
  ##
  private function set_last_error(error, audit, sev)
  {
    dbg::detailed_log(
      lvl: 1,
      src: FUNCTION_NAME,
      msg: "Setting following error",
      msg_details: {
        "error": {"lvl": 1, "value": error}});
    this.last_error_cnt++;
    
    this.last_error['error'] = error;
    this.last_error['audit'] = audit;
    this.last_error['sev'] = sev;
  }
  
  ##
  # Return last_error
  #
  # @return last_error array of values, or NULL if no error was found.
  ##
  public function get_last_error()
  {
    if (this.last_error_cnt > 0)
      return this.last_error;
    else
      return NULL;
  }
  
  ##
  # This is an abstraction of substr so the returned
  # bytes can be reported in multiple formats.
  #
  # @param [types:integer] bitmask of the types you want to return
  # @remark always returns the raw data
  # @remark types 0x02:hexstr, 0x04:raw bitswap, 0x08:hexstr bitswap
  #
  # @return [array] array of the content you requested by format
  ##
  private function get_offset(types)
  {
    local_var buf, start, end, ret, raw, be_raw, i;
    
    buf = _FCT_ANON_ARGS[0];
    start = _FCT_ANON_ARGS[1];
    end = _FCT_ANON_ARGS[2];
    
    ret = make_array();
    raw = substr(buf, start, end);
    if (empty_or_null(raw))
    {
      set_last_error(error:"No buffer passed into get_offset.", sev:1);
      return NULL;
    }
  
    ret['raw'] = raw; #raw 
  
    if (types&0x02)
    {
      ret['hex'] = hexstr(raw); #hexstr
    }
  
    if (types&0x0C)
    {
      be_raw = '';
      for (i=strlen(raw);i>0;i--)
      {
        be_raw += raw[i-1];
      }
  
      if (types&0x04)
      {
        ret['s_raw'] = be_raw; #little endian string
      }
    
      if (types&0x08)
      {
        ret['s_hex'] = hexstr(be_raw); #little endian string
      }
    }
   
    return ret;
  }
  
  ##
  # Parses the resource section of a PE file given 
  # the file handle or raw dump of the rsrc section
  # 
  # @param [rsrc_buf:string] raw rsrc section buffer
  # @param [fh:handle] handle to file to ReadFile content in
  # @param [rsrc_base:integer] offset to rsrc section if using fh
  # @param [rsrc_size:integer] size of rsrc section to read in with fh
  # @param [rsrc_rva:integer] RVA for rsrc section in peHeader section info to get VersionInfo
  # @param [get_types:integer] bitmask used to define what typeof data formats want back, see ``get_offset()``
  # 
  # @return array of the rsrc section parsed for use, or NULL if an error occurred.
  ##
  public function get_rsrc_section(rsrc_buf, fh, rsrc_base, rsrc_size, rsrc_rva, get_types)
  {
    local_var rsrc_section_header, rsrc_section, rsrc_header_base, pe_rsrc_version_info_table, version_info_cnt, version_info_section,
    version_info_rva, version_info_size, i, rsrc, version_info_offset, version_info_split, vi_cache, rsrc_size_cache, rsrc_base_offset;
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "Given get_types",
      msg_details: {
        "get_types": {"lvl": 3, "value": get_types}});
    if (!strlen(rsrc_buf) && fh)
    {
      if (empty_or_null(fh) || empty_or_null(rsrc_base) || empty_or_null(rsrc_size))
      {
        #these values should not be null if we are here
        set_last_error(error:'get_rsrc_section paramters missing\nfh:'+fh+'\nrsrc_base:'+rsrc_base+'\nrsrc_size:'+rsrc_size, sev:1);
        return NULL;
      }
      
      rsrc_buf = "";
      rsrc_size_cache = rsrc_size;
      rsrc_base_offset = rsrc_base;
      while (rsrc_size_cache)
      {
        if (rsrc_size_cache >= 65000)
        {
          rsrc_base_offset = rsrc_size - rsrc_size_cache;
          rsrc_buf += ReadFile(handle:fh, offset:rsrc_base+rsrc_base_offset, length:65000);
          rsrc_size_cache = rsrc_size_cache - 65000;
        }
        else
        {
          rsrc_base_offset = rsrc_size - rsrc_size_cache;
          rsrc_buf += ReadFile(handle:fh, offset:rsrc_base+rsrc_base_offset, length:rsrc_size_cache);
          rsrc_size_cache = 0;
          break;
        }
      }
      
      if (strlen(rsrc_buf) != rsrc_size)
      {
        set_last_error(error:"Failed to read rsrc section from file.", sev:1);
        return NULL;
      }

    }


    if (!strlen(rsrc_buf))
    {
      set_last_error(error:'No handle or buffer provided to get_rsrc_section.', sev:1);
      return NULL;
    }
  
  
    rsrc_section = make_array();
    rsrc_header_base = 0;
    rsrc_section = rsrc_parse_entry(rsrc_buf:rsrc_buf, base_address:rsrc_header_base, get_types:get_types);
    if (!rsrc_section)
    {
      set_last_error(error:'rsrc_parse_entry failed to parse rsrc section.', sev:1);
      return NULL;
    }
    
    # checking required parameters
    if (!rsrc_rva)
    {
      set_last_error(error:"rsrc_rva is null, can't calculate offset for version info.", sev:1);
      return rsrc_section;
    }
  
    ##
    ## rsrc section Version
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-rsrc-section
    ##
    version_info_cnt = 0;
    version_info_section = false;
    foreach rsrc (rsrc_section.entries)
    {
      if (rsrc.entry.s_hex == "00000010") #0x10 Is Version
      {
        version_info_section = true;
        # loop up to 10 deep looking for data section, the standard is 4 
        # deep but there are cases it could be different but 10 should never
        # be reasonably hit here.
        for (i=0;i<10;i++)
        {
          if (rsrc.rsrc_dir)
          {
            rsrc = rsrc.rsrc_dir.entries[0];
          }
          else if (rsrc.data_entry)
          {
            version_info_rva = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, rsrc.data_entry.RVA.raw);
            version_info_size = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, rsrc.data_entry.Size.raw);
            
            # Convert Version RVA to Raw address by subtracting section from rsrc_rva in peHeader
            # Convert RVA to raw offset
            version_info_offset = version_info_rva - rsrc_rva;
            dbg::detailed_log(
              lvl: 3,
              src: FUNCTION_NAME,
              msg: "Version Info section data",
              msg_details: {
                "version_info_rva": {"lvl": 3, "value": version_info_rva},
                "version_info_size": {"lvl": 3, "value": version_info_size},
                "version_info_offset": {"lvl": 3, "value": version_info_offset}});
            vi_cache = get_offset(rsrc_buf, version_info_offset, version_info_offset+version_info_size, types:get_types);
            dbg::detailed_log(
              lvl: 3,
              src: FUNCTION_NAME,
              msg: "Version Info Raw output",
              msg_details: {
                "Data": {"lvl": 3, "value": vi_cache.raw}});
            dbg::detailed_log(
              lvl: 3,
              src: FUNCTION_NAME,
              msg: "Version Info Hex output",
              msg_details: {
                "Data": {"lvl": 3, "value": vi_cache.hex}});
            # Parse the VS_VERSION_INFO table. This is a complicated multi-tier format window,
            # see function header for links to format details
            pe_rsrc_version_info_table = parse_rsrc_version_info(buf:vi_cache.raw, get_types:get_types);
            
            if (pe_rsrc_version_info_table)
            {
              rsrc_section.versionInfo[version_info_cnt] = pe_rsrc_version_info_table;
            }
            else
            {
              dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to Parse rsrc VS_VERSION_INFO section.");
            }
            
            version_info_cnt++;
            break;
          }
          else
          {
            # error is parsing the current rsrc tree jump out of current
            # rsrc section and move to next one
            dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing rsrc_dir or data_entry in rsrc entry.");
            break; 
          }
        }
      }
    }
    
    if (!rsrc_section.versionInfo && version_info_section)
    {
      set_last_error(error:"Failed to parse rsrc section Version Info.", sev:0);
    }
    
    return rsrc_section;
  }
  
  ##
  # Parse the verion 0x10 rsrc section
  # This is a complicated tree of values that 
  # 
  # @param [buf:string] the version buffer in the rsrc section
  # @param [get_types:integer] bitmask used to define what typeof data formats want back, see get_offset()
  #
  # @return array of version info output, or NULL if an error occurred.
  ##
  public function parse_rsrc_version_info(buf, get_types)
  {
    local_var rsrc_vi, VS_FIXEDFILEINFO, current_offset, total_length, 
    stringTable_index, varTable_index, rsrc_vi_string_index, rsrc_vi_var_index, TypeInfo, info_type, 
    TypeInfo_length, typeInfo_check, StringTable_offset, buf_stringTable, is_VarFileInfo, 
    StringTable, StringTable_length, entry_offset, entry_index, entry, is_StringFileInfo,
    entry_length, entry_val_len, entry_data, entry_val, entry_szKey, buf_len,
    entry_val_ascii, entry_szKey_ascii, padding, VarTable_offset, VarTable, 
    VarTable_length, VarTable_val_length, varTable_val_ascii, varTable_szKey_ascii;
    dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "START parsing rsrc_version_info");
    buf_len = strlen(buf);
    if (buf_len < 92)
    {
      set_last_error(error:"The value supplied as rsrc version section is not viable.", sev:0);
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "buf size",
        msg_details: {
          "buf_len": {"lvl": 1, "value": buf_len}});
      return NULL;
    }
    
    ##
    ## -- VS_VERSION_INFO --
    ##

    rsrc_vi = make_array();
    rsrc_vi.wlength = get_offset(buf, 0, 1, types:get_types);
    rsrc_vi.wValueLength = get_offset(buf, 2, 3, types:get_types);
    rsrc_vi.wType = get_offset(buf, 4, 5, types:get_types);
    rsrc_vi.szKey = get_offset(buf, 6, 35, types:get_types);
    rsrc_vi.padding1 = get_offset(buf, 36, 39, types:get_types);
    rsrc_vi.VS_FIXEDFILEINFO = NULL; # VS_FIXEDFILEINFO
    rsrc_vi.padding2 = NULL; #get_offset(buf, 92, 92, types:get_types);
    
    VS_FIXEDFILEINFO = make_array();
    VS_FIXEDFILEINFO.dwSignature = get_offset(buf, 40, 43, types:get_types);
    VS_FIXEDFILEINFO.dwStrucVersion = get_offset(buf, 44, 47, types:get_types);
    VS_FIXEDFILEINFO.dwFileVersionMS = get_offset(buf, 48, 51, types:get_types);
    VS_FIXEDFILEINFO.dwFileVersionLS = get_offset(buf, 52, 55, types:get_types);
    VS_FIXEDFILEINFO.dwProductVersionMS = get_offset(buf, 56, 59, types:get_types);
    VS_FIXEDFILEINFO.dwProductVersionLS = get_offset(buf, 60, 63, types:get_types);
    VS_FIXEDFILEINFO.dwFileFlagsMask = get_offset(buf, 64, 67, types:get_types);
    VS_FIXEDFILEINFO.dwFileFlags = get_offset(buf, 68, 71, types:get_types);
    VS_FIXEDFILEINFO.dwFileOS = get_offset(buf, 72, 75, types:get_types);
    VS_FIXEDFILEINFO.dwFileType = get_offset(buf, 76, 79, types:get_types);
    VS_FIXEDFILEINFO.dwFileSubtype = get_offset(buf, 80, 83, types:get_types);
    VS_FIXEDFILEINFO.dwFileDateMS = get_offset(buf, 84, 87, types:get_types);
    VS_FIXEDFILEINFO.dwFileDateLS = get_offset(buf, 88, 91, types:get_types);
    rsrc_vi.VS_FIXEDFILEINFO = VS_FIXEDFILEINFO;
    
    current_offset = 92;
    total_length = getword(order:BYTE_ORDER_LITTLE_ENDIAN, rsrc_vi.wlength.raw);
    dbg::detailed_log(
      lvl: 2,
      src: FUNCTION_NAME,
      msg: "RSRC Version Info Size",
      msg_details: {
        "total_length": {"lvl": 2, "value": total_length}});
    if (buf_len < total_length)
    {
      set_last_error(error:"The buf supplied is too small; " + buf_len +":"+total_length +".", sev:1);
      return NULL;
    }
    
    stringTable_index = 0;
    varTable_index = 0;
    rsrc_vi_var_index = 0;
    rsrc_vi_string_index = 0;
    while (current_offset < total_length)
    {
      #make sure the offsets are always DWORD aligned
      current_offset += current_offset % 4;
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Version Info current_offset",
        msg_details: {
          "current_offset": {"lvl": 3, "value": current_offset}});
      ## -- StringFileInfo | VarFileInfo--
      ## parse the StringFileInfo or VarFileInfo header
      ## http://winapi.freetechsecrets.com/win32/WIN32VarFileInfo.htm
      ## http://winapi.freetechsecrets.com/win32/WIN32StringFileInfo.htm
      ##
      TypeInfo = make_array();
      TypeInfo.sLength = get_offset(buf, current_offset, current_offset+1, types:get_types);
      TypeInfo.wValueLength = get_offset(buf, current_offset+2, current_offset+3, types:get_types);
      TypeInfo.wType = get_offset(buf, current_offset+4, current_offset+5, types:get_types);
      
      # used to determine if it is binary or string data 0 = binary, 1 = string
      info_type = getword(order:BYTE_ORDER_LITTLE_ENDIAN, TypeInfo.wType.raw);
      TypeInfo_length = getword(order:BYTE_ORDER_LITTLE_ENDIAN, TypeInfo.sLength.raw);
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "[Type]FileInfo size",
        msg_details: {
          "TypeInfo_length": {"lvl": 3, "value": TypeInfo_length}});
      # Get raw output from StringFileInfo | VarFileInfo 
      TypeInfo.raw_buf = get_offset(buf, current_offset, current_offset+TypeInfo_length-1, types:get_types);
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Gathered TypeInfo raw_buf",
        msg_details: {
          "raw_buf": {"lvl": 3, "value": obj_rep(TypeInfo.raw_buf)}});
      if (info_type == 0)
      {
        ## TODO, Currently not supported
        ## Binary data for
        ## -- StringTable --
        ## -- VarTable --
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "[Type]FileInfo Binary Data, currently not supported.");
        current_offset += TypeInfo_length;
      }
      else if (info_type == 1)
      {
        dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg: "[Type]FileInfo String Data");
        # used to determine if StringFileInfo or VarFileInfo by checking for a S or V
        typeInfo_check = get_offset(buf, current_offset+6, current_offset+7, types:get_types);
        dbg::detailed_log(
          lvl: 3,
          src: FUNCTION_NAME,
          msg: "[Type]FileInfo szKey check",
          msg_details: {
            "Check hex": {"lvl": 3, "value": obj_rep(typeInfo_check.hex)}});
        if (typeInfo_check.hex =~ "^5300")
        {

          is_VarFileInfo = false;
          is_StringFileInfo = true;

          # Starts with S is StringFileInfo
          TypeInfo.szKey = get_offset(buf, current_offset+6, current_offset+33, types:get_types);
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "[Type]FileInfo type = StringFileInfo. Showing raw szKey",
            msg_details: {
              "szKey": {"lvl": 3, "value": obj_rep(TypeInfo.szKey.raw)}});
          # StringFileInfo does not align on 32 bit, needs 2 bit padding
          # TypeInfo.padding = get_offset(buf, current_offset+34, current_offset+35, types:get_types);
          StringTable_offset = current_offset+36;
          
          ## String data for
          ## -- StringTable --
          ## -- VarTable --
          ##
          while (StringTable_offset < current_offset + TypeInfo_length)
          {
            buf_stringTable = get_offset(buf, StringTable_offset, StringTable_offset+21, types:get_types);
            StringTable = make_array();
            StringTable.wLength = get_offset(buf, StringTable_offset, StringTable_offset+1, types:get_types);
            StringTable.wValueLength = get_offset(buf, StringTable_offset+2, StringTable_offset+3, types:get_types);
            StringTable.wType = get_offset(buf, StringTable_offset+4, StringTable_offset+5, types:get_types);
            StringTable.szKey = get_offset(buf, StringTable_offset+6, StringTable_offset+24, types:get_types);
            StringTable.String = make_list();
            
            StringTable_length = getword(order:BYTE_ORDER_LITTLE_ENDIAN, StringTable.wLength.raw);
            dbg::detailed_log(
              lvl: 3,
              src: FUNCTION_NAME,
              msg: "StringTable Header",
              msg_details: {
                "Header": {"lvl": 3, "value": obj_rep(buf_stringTable)},
                "StringTable_length": {"lvl": 3, "value": StringTable_length}});
            entry_offset = StringTable_offset+24;
            entry_index = 0;
            while (entry_offset < StringTable_offset+StringTable_length)
            {
              entry = make_array();
              entry.wLength = get_offset(buf, entry_offset, entry_offset+1, types:get_types);
              entry.wValueLength = get_offset(buf, entry_offset+2, entry_offset+3, types:get_types);
              entry_length = getword(order:BYTE_ORDER_LITTLE_ENDIAN, entry.wLength.raw);
              entry_val_len = getword(order:BYTE_ORDER_LITTLE_ENDIAN, entry.wValueLength.raw);

              entry_data = get_offset(buf, entry_offset, entry_offset+entry_length-1, types:get_types);
              
              entry_val = get_offset(buf, entry_offset+entry_length-(entry_val_len*2), entry_offset+entry_length-1, types:get_types);
              entry_szKey = get_offset(buf, entry_offset+6 , entry_offset+entry_length-(entry_val_len*2)-1, types:get_types);
              
              entry_val_ascii = unicode2ascii(string:entry_val.raw);
              entry_szKey_ascii = unicode2ascii(string:entry_szKey.raw);
              
              entry.szKey = entry_szKey;
              entry.value = entry_val;
              entry.szKey_u2a = entry_szKey_ascii;
              entry.value_u2a = entry_val_ascii;

              padding = entry_length%4;
              dbg::detailed_log(
                lvl: 3,
                src: FUNCTION_NAME,
                msg: "Gathered entry information.",
                msg_details: {
                  "entry_length": {"lvl": 3, "value": entry_length},
                  "entry_val_len": {"lvl": 3, "value": entry_val_len},
                  "entry_data": {"lvl": 3, "value": obj_rep(entry_data)},
                  "entry_szKey": {"lvl": 3, "value": obj_rep(entry_szKey)},
                  "entry_szKey_ascii": {"lvl": 3, "value": entry_szKey_ascii},
                  "entry_val": {"lvl": 3, "value": obj_rep(entry_val)},
                  "entry_val_ascii": {"lvl": 3, "value": entry_val_ascii},
                  "padding": {"lvl": 3, "value": padding}});
              entry_offset+= entry_length + padding;
              
              StringTable.String[entry_index] = entry;
              entry_index++;
            }
            
            StringTable_offset += StringTable_length;
            if (!stringTable_index)
            {
              TypeInfo.StringTable = make_list();
            }

            TypeInfo.StringTable[stringTable_index] = StringTable;
            stringTable_index++;

          }

        }
        else if (typeInfo_check.hex =~ "^5600")
        {
          
          is_VarFileInfo = true;
          is_StringFileInfo = false;
          
          # Starts with V is VarFileInfo
          TypeInfo.szKey = get_offset(buf, current_offset+6, current_offset+27, types:get_types);
          dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg: "  - [Type]FileInfo type = VarFileInfo");
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "[Type]FileInfo type = VarFileInfo. Showing raw szKey",
            msg_details: {
              "szKey": {"lvl": 3, "value": obj_rep(TypeInfo.szKey.raw)}});
          VarTable_offset = current_offset+32;
          
          # This is the Var Structure
          # http://winapi.freetechsecrets.com/win32/WIN32Var.htm
          VarTable= make_array();
          VarTable.wLength = get_offset(buf, VarTable_offset, VarTable_offset+1, types:get_types);
          VarTable.wValueLength = get_offset(buf, VarTable_offset+2, VarTable_offset+3, types:get_types);
          VarTable.wType = get_offset(buf, VarTable_offset+4, VarTable_offset+5, types:get_types);
          
          VarTable_length = getword(order:BYTE_ORDER_LITTLE_ENDIAN, VarTable.wLength.raw);
          VarTable_val_length = getword(order:BYTE_ORDER_LITTLE_ENDIAN, VarTable.wValueLength.raw);
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "Gathered different VarTable sizes.",
            msg_details: {
              "VarTable_length": {"lvl": 3, "value": VarTable_length},
              "VarTable_val_length": {"lvl": 3, "value": VarTable_val_length}});
          VarTable.szKey = get_offset(buf, VarTable_offset+6, VarTable_offset+(VarTable_length-VarTable_val_length)-1, types:get_types);
          VarTable.value = get_offset(buf, VarTable_offset+(VarTable_length-VarTable_val_length), VarTable_offset+VarTable_length-1, types:get_types);
          
          varTable_val_ascii = unicode2ascii(string:VarTable.value.raw);
          varTable_szKey_ascii = unicode2ascii(string:VarTable.szKey.raw);
          dbg::detailed_log(
            lvl: 3,
            src: FUNCTION_NAME,
            msg: "Gathered VarTable information.",
            msg_details: {
              "VarTable.szKey": {"lvl": 3, "value": obj_rep(VarTable.szKey)},
              "varTable_szKey_ascii": {"lvl": 3, "value": varTable_szKey_ascii},
              "VarTable.value": {"lvl": 3, "value": obj_rep(VarTable.value)},
              "varTable_val_ascii": {"lvl": 3, "value": varTable_val_ascii}});
          VarTable.szKey_u2a = varTable_szKey_ascii;
          VarTable.value_u2a = varTable_val_ascii;
          
          if (!varTable_index)
          {
            TypeInfo.VarTable = make_list();
          }
          
          TypeInfo.VarTable[varTable_index] = VarTable;
          varTable_index++;
        }
        else
        {
          # something broke this should not be possible
          dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Version Info failed to determine fileinfo type.");
          current_offset += TypeInfo_length;
          continue; # Try to get what data we even if this table parse didn't work
        }
        
        current_offset += TypeInfo_length;
      }
      
      if (is_VarFileInfo)
      {
        rsrc_vi.VarFileInfo[rsrc_vi_var_index] = TypeInfo;
        rsrc_vi_var_index++;
      }
      else if (is_StringFileInfo)
      {
        rsrc_vi.StringFileInfo[rsrc_vi_string_index] = TypeInfo;
        rsrc_vi_string_index++;
      }
      else
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to determine FileInfo type.");
      }
    }
    dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "END parsing rsrc_version_info");
    return rsrc_vi;
  }

  ##
  # This is a helper function for parse_rsrc_version_info.
  # You can use this to obtain just the stringfileinfo strings from
  # the return results to help simplify parsing of the data
  #
  # @param [rsrc_version_info:array] return from ``parse_rsrc_version_info()``.
  # @param [type:integer] NULL or 0 for StringFileInfo, 1 for VarFileInfo .
  # 
  # @return [array] simplified array of the string data
  ##
  public function get_rsrc_version_info_simple_output(rsrc_version_info, type)
  {
    local_var versionInfo_data, versionInfo, StringFileInfo, StringTable, Str, VarFileInfo, VarTable;

    versionInfo_data = make_array();
    if (rsrc_version_info)
    {
      foreach versionInfo (rsrc_version_info)
      {
        if (!type)
        {
          foreach StringFileInfo (versionInfo.StringFileInfo)
          {
            foreach StringTable (StringFileInfo.StringTable)
            {
              foreach Str (StringTable.String)
              {
                if (versionInfo_data[Str.szKey_u2a])
                {
                  versionInfo_data[Str.szKey_u2a] = make_list(versionInfo_data[Str.szKey_u2a],  Str.value_u2a);
                }
                else
                {
                  versionInfo_data[Str.szKey_u2a] = Str.value_u2a;
                }
              }
            }
          }
        }
        
        if (type == 1)
        {
          foreach VarFileInfo (versionInfo.VarFileInfo)
          {
            foreach VarTable (VarFileInfo.VarTable)
            {
              versionInfo_data[VarTable.szKey_u2a] = VarTable.value;
            }
          }
        }
      }
    }  
    else
    {
      set_last_error(error:"No Version Info Supplied to get_rsrc_version_info_simple_output.", sev:1);
      return NULL;
    }

    return versionInfo_data;
  }
  
  ##
  # Takes in an entry from rsrc section and 
  # parses the data recursively.
  #
  # @param [rsrc_buf:string] pointer to rsrc section 
  # @param [base_address:integer] offset to entry to parse
  # @param [get_types:integer] bitmask types from ``get_offset()``
  #  
  # @remark This function is recursive and should parse all subtrees.
  #
  # @return [array] data from current rsrc section
  ##
  private function rsrc_parse_entry(rsrc_buf, base_address, get_types)
  {
    local_var rsrc_section_header, named_sections, id_sections, rsrc_entries_base, 
      count, entry, i, num_entries, offsetToDirectory, rsrc_section, named_section,
      message, rsrc_entry, data_entry;
  
    #return buffer
    rsrc_section = make_array();
  
    # pass in the base to get the entry section header info. Then calculate the number of entries in this section
    rsrc_section.header = parse_rsrc_section_header(rsrc_buf:rsrc_buf, base_address:base_address, get_types:get_types);
    named_sections = getword(order:BYTE_ORDER_LITTLE_ENDIAN, rsrc_section.header.NumberOfNamedEntryies.raw);
    id_sections = getword(order:BYTE_ORDER_LITTLE_ENDIAN, rsrc_section.header.NumberOfIdEntries.raw);
  
    # the section header is 16 bytes so the offset to the first entry is 
    # can be know to be 16 bytes off from base of entry
    rsrc_entries_base = base_address+16;
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "rsrc section named section and ID",
      msg_details: {
        "named_sections": {"lvl": 3, "value": named_sections},
        "id_sections": {"lvl": 3, "value": id_sections}});
    count = named_sections+id_sections;

    
    
    # parse out the current entry's sub trees 
    rsrc_section.entries = parse_rsrc_section_entries(rsrc_buf:rsrc_buf, rsrc_entries_base:rsrc_entries_base ,count:count, get_types:get_types);
    
    num_entries = max_index(rsrc_section.entries);
    if (num_entries < 1)
    {
      set_last_error(error:"rsrc section entry returned less than one entry, should not be possible.", sev:1);
      return NULL;
    }
  
    for (i=0;i<num_entries;i++)
    {
      # get the offset to the current entry in the rsrc section
      offsetToDirectory = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, rsrc_section.entries[i].OffsetToDirectory.raw);
      if (!offsetToDirectory)
      {
        message =  'Could not find offset for rsrc entry \n';
        message += 'rsrc_section.entries[i].OffsetToDirectory.s_hex ' + rsrc_section.entries[i].OffsetToDirectory.s_hex + '\n';
        message += 'rsrc_section.entries[i].entry.s_hex'+rsrc_section.entries[i].entry.s_hex+'\n';
        
        set_last_error(error:message, sev:1);
        return NULL;
      }
      
  
      # 0x80000000 defines the section as an rsrc_directory and not data. So an offset might like 0x800000EC.
      # This means the offset is EC and 0x80000000 defines it as an rsrc_directory and not data.
      if (offsetToDirectory&0x80000000) 
      {
        # This is where re recurse taking our current section and parsing all sub sections
        # so that each entry in the tree is processed before moving onto the next entry. 
        # This is a common technique for crawling data structures that are not too deep 
        # and dogpiling the data back
        rsrc_entry = rsrc_parse_entry(rsrc_buf:rsrc_buf, base_address:offsetToDirectory&0x00FFFFFF, get_types:get_types);
        if (!rsrc_entry) 
        {
          # returned null fail back out of recursion
          # error reporting should be handled at the failure up stream
          # and not in each recursion
          return NULL;
        }
        rsrc_section.entries[i].rsrc_dir = rsrc_entry;
      }
      else
      {
        #if the section is data we save this back into data_entry with the points to the size and RVA of the data
        data_entry = rsrc_parse_data_entry(rsrc_buf:rsrc_buf, base_address:offsetToDirectory&0x00FFFFFF, get_types:get_types);
        if (!data_entry)
        {
          set_last_error(error:"Failed to parse the data_entry for rsrc section.", sev:1);
          return NULL;
        }
        
        rsrc_section.entries[i].data_entry = data_entry;
        
      }
    }
    
    return rsrc_section;
  }
  
  ##
  # Parse the rsrc section data_entry entries.
  # This is a strait forward 16 byte (four 4byte values).
  # 
  # @param [rsrc_buf:string] pointer to rsrc_buf section with data_entry in it.
  # @param [base_address:integer] offset to the base of the data_entry section in rsrc_buf.
  # @param [get_types:integer] bitmask types from ``get_offset()``
  #
  # @return [array] The array of data_entry values.
  ##
  private function rsrc_parse_data_entry(rsrc_buf, base_address, get_types)
  {
    local_var data_entry;
  
    data_entry = make_array();
    data_entry.RVA = get_offset(rsrc_buf, base_address+0, base_address+3, types:get_types);;
    data_entry.Size = get_offset(rsrc_buf, base_address+4, base_address+7, types:get_types);;
    data_entry.CodePage = get_offset(rsrc_buf, base_address+8, base_address+11, types:get_types);;
    data_entry.Reserved = get_offset(rsrc_buf, base_address+12, base_address+15, types:get_types);;
    
    return data_entry;
  }
  
  ##
  # Takes in a buffer and parses it out into rsrc header.
  # 
  # @param [rsrc_buf:string] a buffer with the rsrc header in it.
  # @param [base_address:integer] offset in rsrc_buf the rsrc header is located.
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  # 
  # @return [array] The array of parsed data.
  ##
  private function parse_rsrc_section_header(rsrc_buf, base_address, get_types)
  {
    local_var rsrc_section_header;
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "Given base_address",
      msg_details: {
        "base_address": {"lvl": 3, "value": base_address}});
    ##
    ## rsrc section headers
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-rsrc-section
    ##
    rsrc_section_header.Characteristics = get_offset(rsrc_buf, base_address+0, base_address+3, types:get_types);
    rsrc_section_header.TimeDateStamp = get_offset(rsrc_buf, base_address+4, base_address+7, types:get_types);
    rsrc_section_header.MajorVersion = get_offset(rsrc_buf, base_address+8, base_address+9, types:get_types);
    rsrc_section_header.MinorVersion = get_offset(rsrc_buf, base_address+10, base_address+11, types:get_types);
    rsrc_section_header.NumberOfNamedEntryies = get_offset(rsrc_buf, base_address+12, base_address+13, types:get_types);
    rsrc_section_header.NumberOfIdEntries = get_offset(rsrc_buf, base_address+14, base_address+15, types:get_types);
  
    return rsrc_section_header;
  }
  
  ##
  # Takes in a buffer with ``rsrc_directory`` entries
  # and parses them into an array.
  # 
  # @param [rsrc_buf:string] buffer with ``rsrc_directory`` in it
  # @param [count:integer] number of entries to parse in ``rsrc_buf``
  # @param [rsrc_entries_base:integer] offset in ``rsrc_buf`` of first entry
  # @param [get_types:integer] bitmask types from ``get_offset()``
  #
  # @return [array] The array of rsrc entries.
  ##
  private function parse_rsrc_section_entries(rsrc_buf, count, rsrc_entries_base, get_types)
  {
    ##
    ## rsrc section entries
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-rsrc-section
    ##
    local_var rsrc_entries, entryIdLoc, OffsetToDirectoryLoc, i;
  
    rsrc_entries = make_list();
  
    for (i=0; i<count; i++)
    {
      rsrc_entries[i] = make_array();
      entryIdLoc = rsrc_entries_base + (i*8);
      OffsetToDirectoryLoc = entryIdLoc+4;
      
      rsrc_entries[i].entry = get_offset(rsrc_buf, entryIdLoc, entryIdLoc+3, types:get_types);
      rsrc_entries[i].OffsetToDirectory = get_offset(rsrc_buf, OffsetToDirectoryLoc, OffsetToDirectoryLoc+3, types:get_types);
    }
  
    return rsrc_entries;
  }
  
  ##
  # Parse the DOSHeader section of a PE file.
  # Reference: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
  # 
  # @param [buf:string] buffer that contains DOSHeader.
  # @param [offset:integer] offset in buf that DOSHeader is located.
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  # 
  # @return [array] The array containing the parsed version of DOS Header.
  ##
  public function get_DOSHeader(buf, offset, get_types)
  {
    local_var DOSHeader;
  
    if (isnull(offset)) offset = 0;
  
    DOSHeader.DOSHeader = get_offset(buf,offset+0,offset+60);
    DOSHeader.Signature = get_offset(buf, offset+0, offset+1);
    DOSHeader.LastPage = get_offset(buf, offset+2, offset+3, types:get_types); 
    DOSHeader.Pages = get_offset(buf, offset+4, offset+5, types:get_types); 
    DOSHeader.Relocations = get_offset(buf, offset+6, offset+7, types:get_types); 
    DOSHeader.SizeOfHeader = get_offset(buf, offset+8, offset+9, types:get_types); 
    DOSHeader.MinParagraph = get_offset(buf, offset+10, offset+11, types:get_types); 
    DOSHeader.MaxParagraph = get_offset(buf, offset+12, offset+13, types:get_types); 
    DOSHeader.InitialSS = get_offset(buf, offset+14, offset+15, types:get_types); 
    DOSHeader.InitialSP = get_offset(buf, offset+16, offset+17, types:get_types); 
    DOSHeader.Checksum = get_offset(buf, offset+18, offset+19, types:get_types); 
    DOSHeader.InitiailIP = get_offset(buf, offset+20, offset+21, types:get_types); 
    DOSHeader.InitialCS = get_offset(buf, offset+22, offset+23, types:get_types); 
    DOSHeader.RelocationTable = get_offset(buf, offset+24, offset+25, types:get_types); 
    DOSHeader.OverlayNum = get_offset(buf, offset+26, offset+27, types:get_types); 
    DOSHeader.Reserved1 = get_offset(buf, offset+28, offset+35, types:get_types); 
    DOSHeader.OEMIdentifier = get_offset(buf, offset+36, offset+37, types:get_types); 
    DOSHeader.OEMInfo = get_offset(buf, offset+38, offset+39, types:get_types);
    DOSHeader.Reserved2 = get_offset(buf, offset+40, offset+59, types:get_types);
    DOSHeader.OffsetToExe = get_offset(buf, offset+60, offset+63, types:get_types);
  
    return DOSHeader;
  }
  
  ##
  # Get the DOS stub from a PE buffer.
  # References: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers ,
  # https://marcin-chwedczuk.github.io/a-closer-look-at-portable-executable-msdos-stub
  # 
  # @param [buf:string] buffer that contains DOSStub.
  # @param [offset:integer] offset in buf that DOSStub is located.
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  # 
  # @return [array] The array containing the parsed info of DOS Header.
  ##
  public function get_DOSStub(buf, offset, get_types)
  {
    if (isnull(offset)) offset = 0;
    return get_offset(buf,offset,offset+159, types:get_types);
  }
  
  ##
  # Get the IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER PE Signature.
  # Reference: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
  #
  # @param [buf:string] buffer that contains PE Signature.
  # @param [offset:integer] offset in buf that PE Signature is located.
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  # 
  # @return [string] The string of PE Signature, should always be "PE\0\0"
  ##
  public function get_pe_signature(buf, offset, get_types)
  {
    if (isnull(offset)) offset = 0;
    return get_offset(buf, offset, offset+3, types:get_types);
  }
  
  ##
  # Get ``IMAGE_NT_HEADERS.IMAGE_FILE_HEADER`` from buffer.
  # Reference: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
  #
  # @param [buf:string] buffer that contains ``IMAGE_FILE_HEADER``.
  # @param [offset:integer] offset in buf that ``IMAGE_FILE_HEADER`` is located.
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  #
  # @return [array] The array containing the parsed info for ``IMAGE_FILE_HEADER``.
  ##
  public function get_image_file_header(buf, offset, get_types)
  {
    local_var IMAGE_FILE_HEADER;
  
    if (isnull(offset)) offset = 0;
  
    IMAGE_FILE_HEADER.IMAGE_FILE_HEADER = get_offset(buf, offset+4, offset+23);
    IMAGE_FILE_HEADER.Machine = get_offset(buf, offset+4, offset+5 , types:get_types);
    IMAGE_FILE_HEADER.NumSections = get_offset(buf, offset+6, offset+7, types:get_types);
    IMAGE_FILE_HEADER.Timestamp = get_offset(buf, offset+8, offset+11, types:get_types);
    IMAGE_FILE_HEADER.SymbolsTable = get_offset(buf, offset+12, offset+15, types:get_types);
    IMAGE_FILE_HEADER.NumSymbols = get_offset(buf, offset+16, offset+19, types:get_types);
    IMAGE_FILE_HEADER.SizeOfOptionalHeader = get_offset(buf, offset+20, offset+21, types:get_types);
    IMAGE_FILE_HEADER.Characteristics = get_offset(buf, offset+22, offset+23, types:get_types);
  
    return IMAGE_FILE_HEADER;
  }
  
  ##
  # Get ``IMAGE_NT_HEADERS.IMAGE_OPTIONA_HEADER`` from buffer.
  # Reference: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
  #
  # @param [buf:string] buffer that contains ``IMAGE_OPTIONAL_HEADER``
  # @param [offset:integer] offset in buf that ``IMAGE_OPTIONAL_HEADER`` is located
  # @param [sizeOfOptionalHeader:integer] ``IMAGE_FILE_HEADER.SizeOfOptionalHeader``
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  #
  # @return [array] The array containing the parsed info for ``IMAGE_OPTIONAL_HEADER``.
  ##
  public function get_image_optional_header(buf, offset, sizeOfOptionalHeader, get_types)
  {
    local_var IMAGE_OPTIONAL_HEADER;
    
    if (isnull(offset)) offset = 0;
    
    IMAGE_OPTIONAL_HEADER.IMAGE_OPTIONAL_HEADER = get_offset(buf, offset, offset+sizeOfOptionalHeader);
    IMAGE_OPTIONAL_HEADER.Magic = get_offset(buf, offset, offset+1, types:get_types);
    IMAGE_OPTIONAL_HEADER.MajorLinkerVersion = get_offset(buf, offset+2, offset+2, types:get_types);
    IMAGE_OPTIONAL_HEADER.MinorLinkerVersion = get_offset(buf, offset+3, offset+3, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfCode = get_offset(buf, offset+4, offset+7, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfInitializedData = get_offset(buf, offset+8, offset+11, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfUninitializedData = get_offset(buf, offset+12, offset+15, types:get_types);
    IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint = get_offset(buf, offset+16, offset+19, types:get_types);
    IMAGE_OPTIONAL_HEADER.BaseOfCode = get_offset(buf, offset+20, offset+23, types:get_types);
    IMAGE_OPTIONAL_HEADER.BaseOfData = get_offset(buf, offset+24, offset+27, types:get_types);
    IMAGE_OPTIONAL_HEADER.ImageBase = get_offset(buf, offset+28, offset+31, types:get_types);
    IMAGE_OPTIONAL_HEADER.SectionAlignment = get_offset(buf, offset+32, offset+35, types:get_types);
    IMAGE_OPTIONAL_HEADER.FileAlignment = get_offset(buf, offset+36, offset+39, types:get_types);
    IMAGE_OPTIONAL_HEADER.MajorOSVersion = get_offset(buf, offset+40, offset+41, types:get_types);
    IMAGE_OPTIONAL_HEADER.MinorOSVersion = get_offset(buf, offset+42, offset+43, types:get_types);
    IMAGE_OPTIONAL_HEADER.MajorImageVersion = get_offset(buf, offset+44, offset+45, types:get_types);
    IMAGE_OPTIONAL_HEADER.MinorImageVersion = get_offset(buf, offset+46, offset+47, types:get_types);
    IMAGE_OPTIONAL_HEADER.MajorSubsystemVersion = get_offset(buf, offset+48, offset+49, types:get_types);
    IMAGE_OPTIONAL_HEADER.MinorSubsystemVersion = get_offset(buf, offset+50, offset+51, types:get_types);
    IMAGE_OPTIONAL_HEADER.Win32VersionValue = get_offset(buf, offset+52, offset+55, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfImage = get_offset(buf, offset+56, offset+59, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfHeader = get_offset(buf, offset+60, offset+63, types:get_types);
    IMAGE_OPTIONAL_HEADER.Checksum = get_offset(buf, offset+64, offset+67, types:get_types);
    IMAGE_OPTIONAL_HEADER.Subsystem = get_offset(buf, offset+68, offset+69, types:get_types);
    IMAGE_OPTIONAL_HEADER.DLLCharacteristics = get_offset(buf, offset+70, offset+71, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfStackReserve = get_offset(buf, offset+72, offset+75, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfStackCommit = get_offset(buf, offset+76, offset+79, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfHeapReserve = get_offset(buf, offset+80, offset+83, types:get_types);
    IMAGE_OPTIONAL_HEADER.SizeOfHeapCommit = get_offset(buf, offset+84, offset+87, types:get_types);
    IMAGE_OPTIONAL_HEADER.LoadFlags = get_offset(buf, offset+88, offset+91, types:get_types);
    IMAGE_OPTIONAL_HEADER.NumberOfDataDirectories = get_offset(buf, offset+92, offset+95, types:get_types);
    
    return IMAGE_OPTIONAL_HEADER;
  }
  
  ##
  # Get ``IMAGE_NT_HEADERS.IMAGE_OPTIONA_HEADER.DataDirectories`` from buffer.
  # Reference: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
  #
  # @param [buf:string] buffer that contains ``DataDirectories``
  # @param [offset:integer] offset in buf that ``DataDirectories`` is located
  # @param [numSections:integer] ``IMAGE_OPTIONAL_HEADER.NumberOfDataDirectories``
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  #
  # @return [array] The array containing the parsed info for DataDirectories.
  ##
  public function get_data_directories(buf, offset, numDataDir, get_types)
  {
    local_var dd_entries, dd_entry_offset, dd_entry, i, DataDirectories;
    
    dd_entries = ["Export","Import","Resource","Exception",
                  "Certificate","BaseRelocation","Debug","Architecture",
                  "GlobalPtr", "TLS","LoadConfig","BoundImport",
                  "IAT", "DelayImport","CLRRuntimeHeader","Reserved"];
    
    DataDirectories = make_array();
    for (i=0; i<numDataDir; i++)
    {
      dd_entry_offset = offset + (i*8);
      dd_entry = make_array("dd_entry_rva", get_offset(buf, dd_entry_offset, dd_entry_offset+3, types:get_types),
                            "dd_entry_size", get_offset(buf, dd_entry_offset+4, dd_entry_offset+7, types:get_types));
      
      DataDirectories[dd_entries[i]] = dd_entry;
    }
    
    return DataDirectories;
  }

  ##
  # Get ``IMAGE_SECTION_HEADER`` from buffer.
  # References: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#section-table-section-headers
  #
  # @param [buf:string] buffer that contains ``IMAGE_SECTION_HEADER``
  # @param [offset:int] offset in buf that ``IMAGE_SECTION_HEADER`` is located
  # @param [numSections:int] ``IMAGE_NT_HEADER.IMAGE_FILE_HEADER.NumSections``
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  #
  # @return [array] The array containing the parsed info for ``IMAGE_SECTION_HEADER``.
  ##
  public function get_image_section_header(buf, offset, numSections, get_types)
  {
    local_var section_entry_offset, i, section_info, IMAGE_SECTION_HEADER, title;
  
    for (i=0; i<numSections; i++)
    {
      section_entry_offset = offset + (i*40);
      section_info = make_array("Name", get_offset(buf, section_entry_offset , section_entry_offset+7, types:get_types),
                               "VirtualSize", get_offset(buf, section_entry_offset+8 , section_entry_offset+11, types:get_types),
                               "RVA", get_offset(buf, section_entry_offset+12 , section_entry_offset+15, types:get_types),
                               "SizeOfRawData", get_offset(buf, section_entry_offset+16 , section_entry_offset+19, types:get_types),
                               "PointerToRawData", get_offset(buf, section_entry_offset+20 , section_entry_offset+23, types:get_types),
                               "PointerToRelocations", get_offset(buf, section_entry_offset+24 , section_entry_offset+27, types:get_types),
                               "PointerToLineNumbers", get_offset(buf, section_entry_offset+28 , section_entry_offset+31, types:get_types),
                               "NumberOfRelocations", get_offset(buf, section_entry_offset+32 , section_entry_offset+33, types:get_types),
                               "NumberOfLineNumbers", get_offset(buf, section_entry_offset+34 , section_entry_offset+35, types:get_types),
                               "Characteristics", get_offset(buf, section_entry_offset+36 , section_entry_offset+39, types:get_types)
      );
      
      title = get_ascii_printable(string:section_info.Name.raw);
      
      if (title)
      {
        IMAGE_SECTION_HEADER[title] = section_info;
      }
      else
      {
        set_last_error(error:"Failed to obtain section title.", sev:1);
        return NULL;
      }
    }
    
    return IMAGE_SECTION_HEADER;
  }
  
  ##
  # Parses a buffer that starts with PEHEader 
  # and returns a stuctured array of the data
  # as far as it can parse.
  #
  # @param [buf:string] buffer that starts with PEHeader
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  #
  # @remark this parses from DOSHeader to IMAGE_SECTION_HEADER
  #
  # @return [array] The array containing the PEHeader info.
  ##
  public function parse_PEHeader(buf, get_types)
  {
    local_var neededSize, peHeader, offset_to_exe, file_header_size, sizeOfOptionalHeader, 
              optional_header_base, dd_entry_base, numDataDir, numSections, section_base, buf_len;

    
    buf_len = strlen(buf);
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "Computed buf_len",
      msg_details: {
        "buf_len": {"lvl": 3, "value": buf_len}});
    ##
    ## DOSHeader
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
    ##
    neededSize = 64;
    if (neededSize > buf_len)
    {
      set_last_error(error:"The buffer supplied is too small.", sev:1);
      return NULL;
    }
    peHeader = {};
    dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg: "Getting DOSHeader");
    peHeader.DOSHeader = get_DOSHeader(buf:buf, get_types:get_types);

    #validate MZ signature 
    if (peHeader.DOSHeader.Signature.raw != "MZ")
    {
      set_last_error(error:"DOSHeader.Signature does not equal MZ.", sev:1);
      return NULL;
    }

    ##
    ## DOSStub
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
    ##
    neededSize = 223;
    if (neededSize > buf_len) return peHeader;
    dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg: "Getting DOSStub");
    peHeader.DOSStub = get_DOSStub(buf:buf, get_types:get_types);

    if(!substr(peHeader.DOSStub.raw, 78, 115) == "This program cannot be run in DOS mode")
    {
      set_last_error(error:"DOSStub does not contain 'This program cannot be run in DOS mode' of offset 78", sev:1);
      return NULL;
    }
  
    ##
    ## IMAGE_NT_HEADER
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
    ##
    # get base raw offset
    offset_to_exe = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, peHeader.DOSHeader.OffsetToExe.raw);
    
    ##
    ## IMAGE_NT_HEADER.Signature
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
    ##  
    neededSize = offset_to_exe+3;
    if (neededSize > buf_len) return peHeader;
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "IMAGE_NT_HEADER.Signature offset",
      msg_details: {
        "offset_to_exe": {"lvl": 3, "value": offset_to_exe}});
    peHeader.IMAGE_NT_HEADER.Signature = get_pe_signature(buf:buf ,offset:offset_to_exe, get_types:get_types);

    # Validate PE Signature
    if (!peHeader.IMAGE_NT_HEADER.Signature.raw == 'PE\0\0')
    {
      set_last_error(error:"peHeader.IMAGE_NT_HEADER.Signature does not equal PE\0\0", sev:1);
      return NULL;
    }
    
    ##
    ## IMAGE_NT_HEADER.IMAGE_FILE_HEADER
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
    ##  
    file_header_size = 24;
    neededSize = offset_to_exe+23;
    if (neededSize > buf_len) return peHeader;
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "IMAGE_FILE_HEADER offset",
      msg_details: {
        "offset_to_exe": {"lvl": 3, "value": offset_to_exe}});
    peHeader.IMAGE_NT_HEADER.IMAGE_FILE_HEADER = get_image_file_header(buf:buf, offset:offset_to_exe, get_types:get_types);
  
    ##
    ## IMAGE_NT_HEADER.IMAGE_FILE_HEADER
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
    ##  
    sizeOfOptionalHeader = getword(order:BYTE_ORDER_LITTLE_ENDIAN, peHeader.IMAGE_NT_HEADER.IMAGE_FILE_HEADER.SizeOfOptionalHeader.raw);
    neededSize = offset_to_exe+file_header_size+sizeOfOptionalHeader;
    if (neededSize > buf_len) return peHeader;
    optional_header_base = offset_to_exe+file_header_size;
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "IMAGE_FILE_HEADER offset",
      msg_details: {
        "optional_header_base": {"lvl": 3, "value": optional_header_base}});
    peHeader.IMAGE_NT_HEADER.IMAGE_OPTIONAL_HEADER = get_image_optional_header(buf:buf, offset:optional_header_base, sizeOfOptionalHeader:sizeOfOptionalHeader, get_types:get_types);
  
    ##
    ## DataDirectories
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#file-headers 
    ## 
    dd_entry_base = offset_to_exe+120; # dec offset from peHeader.IMAGE_NT_HEADER base
    numDataDir = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, peHeader.IMAGE_NT_HEADER.IMAGE_OPTIONAL_HEADER.NumberOfDataDirectories.raw);
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "DataDirectories offset and numDataDir",
      msg_details: {
        "dd_entry_base": {"lvl": 3, "value": dd_entry_base},
        "numDataDir": {"lvl": 3, "value": numDataDir}});
    peHeader.IMAGE_NT_HEADER.IMAGE_OPTIONAL_HEADER.DataDirectories = get_data_directories(buf:buf, offset:dd_entry_base, numDataDir:numDataDir, get_types:get_types);
    
    ##
    ## Sections
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#section-table-section-headers
    ##
    numSections = getword(order:BYTE_ORDER_LITTLE_ENDIAN, peHeader.IMAGE_NT_HEADER.IMAGE_FILE_HEADER.NumSections.raw);  
    neededSize = offset_to_exe+file_header_size+sizeOfOptionalHeader+(numSections*40);
    if (neededSize > buf_len) return peHeader;
    section_base = offset_to_exe+file_header_size+sizeOfOptionalHeader;
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "IMAGE_SECTION_HEADER offset and numSections",
      msg_details: {
        "section_base": {"lvl": 3, "value": section_base},
        "numSections": {"lvl": 3, "value": numSections}});
    peHeader.IMAGE_SECTION_HEADER = get_image_section_header(buf:buf, offset:section_base, numSections:numSections, get_types:get_types);
    
    return peHeader;
  }
  
  ##
  # Base Entry to automate parsing a PE file
  # on a remote system. This will just take a
  # file path and should return a formatted array
  # full of PE data.
  # 
  # @param [file_path:string] full windows file path to file, this or buf
  # @param [buf:string] A File with PE format, this or file_path
  # @param [get_types:integer] bitmask types from ``get_offset()``.
  #
  # @remark this function is used to parse the entire PE file
  #   if you want to parse specific parts of a PE file look
  #   to those specific calls such has ``pe_parse.parse_PEHeader()``
  # 
  # @return [array] The array containing the PE data, can use dump_table(table:ret) to see content 
  # and understand the layout. Or NULL if an error occurred.
  ##
  public function getFilePEInfo(file_path, buf, get_types)
  {
    local_var name,port,login,pass,domain,share,rc,filename,fh,
              peHeader,rsrc_base,rsrc_size,rsrc_rva,rsrc_buf,
              text_buf,text_base;
    
    # default to gathering all types if not specified
    if (isnull(get_types)) get_types = 0x0F;
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "Using following get_types value",
      msg_details: {
        "get_types": {"lvl": 3, "value": get_types}});
    if (file_path)
    {
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "Using following file_path",
        msg_details: {
          "file_path": {"lvl": 2, "value": file_path}});
      name    =  kb_smb_name();
      port    =  kb_smb_transport();
      login   =  kb_smb_login();
      pass    =  kb_smb_password();
      domain  =  kb_smb_domain();
      
      share = preg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file_path);
      if(!smb_session_init())
      {
        set_last_error(error:"Failed to create smb_session_init.", sev:1);
        return NULL; # audit(AUDIT_FN_FAIL, 'smb_session_init');
      }
      
      # Connect to the share software is installed on.
      rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
      if ( rc != 1 )
      {
        NetUseDel();
        set_last_error(error:"Failed to connect to " + share + " share.", sev:1);
        return NULL;
      }
      
      filename = preg_replace(pattern:"^[A-Za-z]:(.*)", replace:'\\1\\', string:file_path);
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Sanitized filename",
        msg_details: {
          "filename": {"lvl": 3, "value": filename}});
      fh = CreateFile(
        file:filename,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      
      if (fh)
      {
        # Read in the first 1024 bytes of the PE file
        buf = ReadFile(handle:fh, offset:0, length:1024);
      }
      else
      {
        NetUseDel();
        set_last_error(error:"getFilePEInfo Failed to create File Handle to file path.", sev:1);
        return NULL;
      }
    }

    if (!strlen(buf))
    {
      if (fh) CloseFile(handle:fh);
      NetUseDel();
      set_last_error(error:'getFilePEInfo is missing a buf', sev:1);
      return NULL;
    }
    
    ##
    ## Parse the PE header from the remote file
    ##
    peHeader = parse_PEHeader(buf:buf, get_types:get_types);
    if (!peHeader)
    {
      if (fh) CloseFile(handle:fh);
      NetUseDel();
      set_last_error(error:'Failed to Parse PEHeader on target \n' + file_path, sev:1);
      return NULL;
    }
    
    ##
    ## rsrc section
    ## https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-rsrc-section
    ##
    if (peHeader.IMAGE_SECTION_HEADER['.rsrc'])
    {
      rsrc_base = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, peHeader.IMAGE_SECTION_HEADER['.rsrc'].PointerToRawData.raw);
      rsrc_size = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, peHeader.IMAGE_SECTION_HEADER['.rsrc'].SizeOfRawData.raw);
      rsrc_rva = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, peHeader.IMAGE_SECTION_HEADER['.rsrc'].RVA.raw);
      dbg::detailed_log(
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Gathered following variables",
        msg_details: {
          "rsrc_base": {"lvl": 3, "value": rsrc_base},
          "rsrc_size": {"lvl": 3, "value": rsrc_size},
          "rsrc_rva": {"lvl": 3, "value": rsrc_rva}});
      if (fh)
      {
        dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "Getting rsrc section from file handle.");
        peHeader.rsrc = get_rsrc_section(fh:fh, rsrc_base:rsrc_base, rsrc_size:rsrc_size, rsrc_rva:rsrc_rva, get_types:get_types);
      }
      else
      {
        dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "Getting rsrc section from local buffer.");
        rsrc_buf = substr(buf, rsrc_base, rsrc_base+rsrc_size);
        
        peHeader.rsrc = get_rsrc_section(rsrc_buf:rsrc_buf, rsrc_base:rsrc_base, rsrc_size:rsrc_size, rsrc_rva:rsrc_rva, get_types:get_types);
      }
      
      if (!peHeader.rsrc)
      {
        if (fh) CloseFile(handle:fh);
        NetUseDel();
        set_last_error(error:'Failed to Parse rsrc section on target \n' + file_path, sev:1);
        return NULL;
      }
    }
    else
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "File does not have a rsrc section");
    }

    ##
    ## text stub
    ##
    text_base = getdword(order:BYTE_ORDER_LITTLE_ENDIAN, peHeader.IMAGE_SECTION_HEADER['.text'].PointerToRawData.raw);
    if (fh)
    {
      text_buf = ReadFile(handle:fh, offset:text_base, length:64);
    }
    else
    {
      text_buf = substr(buf, text_base, text_base+64);
    }
    peHeader.textStub = hexstr(text_buf);
    
    ##
    ## EP Stub
    ## TODO
    
    
    ##
    ## Import Address Table
    ## TODO
    
    
    ##
    ## Export Address Table
    ## TODO
    
    

    if (fh) CloseFile(handle:fh);
    NetUseDel();

    return peHeader;
  }

  ##
  # Used to print debug messages primarily in ``test_getFilePEInfo()``.
  # 
  # @anonparam [1st:string] message to print
  # @param [table:array|list] output to dump_table
  #
  # @remark what is displayed is handled in the DEBUG member variable
  # see the constructor for setting this
  ##
  private function dbg_print(table)
  {
    # print of anon arg and debug is set and no table data
    if (_FCT_ANON_ARGS[0] && this.DEBUG & 0x01 && !table)
    {
      display(_FCT_ANON_ARGS[0]);
    }
    
    if (table && this.DEBUG & 0x02)
    {
      dump_table(table:table);
    }
  }
  
  ##
  # Used for CLI testing of the parser
  ##
  public function test_getFilePEInfo(list_of_files)
  {
    local_var PE, file, StringFileInfo_versionInfo, VarFileInfo_versionInfo, section;
    
    # setup creds for targets system
    set_kb_item(name:"SMB/Registry/Enumerated", value:TRUE);
    set_kb_item(name:"SMB/registry_full_access", value:TRUE);
    set_kb_item(name:"SMB/name" ,value:get_host_ip());
    set_kb_item(name:"SMB/transport", value:445);
    set_kb_item(name:"SMB/login", value:"username");
    set_kb_item(name:"SMB/password", value:"password");

    # some default files to test if none are added
    if (isnull(list_of_files))
    {
      list_of_files = [
        "C:\\Windows\\notepad.exe",
        "C:\\Windows\\regedit.exe",
        "C:\\Windows\\write.exe"
      ];
    }

    # cycle through all listed files
    var fcount = 0; # keep track of how many files
    foreach file (list_of_files)
    {
      this.dbg_print('>>>>>>>>>>>>> '+file+' <<<<<<<<<<<<<<<\n');
      PE = getFilePEInfo(file_path:file);
      
      if (isnull(PE))
      {
        this.dbg_print('Failed to parse File.\n');
        continue;
      }
      
      fcount++;
      
      # If you want to see all the raw data from the table
      this.dbg_print(table:PE, 'PE table full dump\n');

      ## A list of a few data points to make sure return looks good      

      # Report DOSHeader Signature MZ
      this.dbg_print("DOSHeader Signature : "+ PE.DOSHeader.Signature.raw + '\n');

      # Report PE Signature
      this.dbg_print("PE Signature : "+ join(sep:" , ", PE.IMAGE_NT_HEADER.Signature) + '\n');

      # Report PEHeader timestamp
      this.dbg_print("PEHeader Timestamp : " + PE.IMAGE_NT_HEADER.IMAGE_FILE_HEADER.Timestamp.hex + '\n');

      # Report .text stub
      this.dbg_print("PE .text section stub : "+ PE.textStub + '\n');
      
      # Report sections
      this.dbg_print('list of the sections by name\n');
      foreach section (keys(PE.IMAGE_SECTION_HEADER))
      {
        this.dbg_print("  "+section);
      }
      this.dbg_print('\n');
      
      # Get version info from file
      if (PE.rsrc.versionInfo)
      {
        StringFileInfo_versionInfo = get_rsrc_version_info_simple_output(rsrc_version_info:PE.rsrc.versionInfo, type:0);
        this.dbg_print(table:StringFileInfo_versionInfo, 'Version Info StringFileInfo.\n');

        VarFileInfo_versionInfo = get_rsrc_version_info_simple_output(rsrc_version_info:PE.rsrc.versionInfo, type:1);
        this.dbg_print(table:VarFileInfo_versionInfo, 'Version Info VarFileInfo.\n');
      }
      else
      {
        this.dbg_print('No VersionInfo For this file.\n');
      }
      
      # used to prompt between files to allow review of information
      if (this.DEBUG)
      {
        display("Press Enter to Continue >>");
        prompt();
      }
    }
    this.dbg_print(fcount);
  }
}

## Used for testing of library on cli
#test_pe = new("pe_parser", 1);
#test_pe.test_getFilePEInfo();
