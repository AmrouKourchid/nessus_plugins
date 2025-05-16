#TRUSTED 3caf1aab06ec898406e1d6ec7015de1b442deed0811e6e7fc12bf6eda127b5e6557ddeeb38478b80d06789e0f56d508fab216cef8aee4384a7d0fa8b751e922508903ceca03c087d3ef427de6df3fa733f6bd67fd506a2886a1abce48ac005e66b0b231425238a3818389f78cbf8abff941f230b5481b4d8138240f6244312d40e21bf0085291d825867861b13dbd53397f4215818129874fc8896637e7f0708542f8d5a5afc2a79ac2d71ea44f0cc336c77ba41435cd5d28085a41aa0eccde4136a14903ce5c38a62eecd099b887b85a013d3b2b77b0b3d3767b006f6725b6212302499a7239e242be87d5f480986f535a9fcefea823cc66062378397dc37195ebc3e65de9c1f859a8ed21f00ef1d3e3a2577cd6b7f117b1e96271ad9f43f0b5ebfe228c56c351bdd844d2cd9dc168ec274444ba1ff9a3b7757dd5310ac82242d4dd8dc7146e5997ab9c4c37ee3a028c5a5cad4144db42cd9bb778777f075e8e5d545faf28f124dee916eca3aad9aef432ffbf6c0e1014b2d9fea483089c92399e6e3917546e67a4a1927bf153075b611710a5d592d6eba5365c97fe9f06e77205d06e3dc07f9d6c11152b03d40c5081f7704bf91e755415b114ec6563cd9a3744001e7988d3df31b9210d5c35e54b57316e3c2ce9c555acf969322ea0749214bf2920ebe13af112ad8b078a6258c336b255020ee6124ee4f2374ae29035676
#TRUST-RSA-SHA256 8d40968a200104b382b22cd0c3a958de988b3c80b24d530b2f73325ab4c4eaec83e8c24c307d6979c70651e2810f3ac418e46e6c85084fd303ece20db70664fa7c86ec8c090c8f09e52c117ddf227aa05cc17298b871f98741233717e0d1cb2d31f02a84650fd7610daf02cb50832b545fe8308a6650eb93a27ee0e891b173beb8e28e6b2e0538661c125f3d296c4759b1937dfac1113991521d9963e642557f231eb27f3b21e3e7009a9f2cce0e72a6fe4f9817f901378a9c08ba60460a29e90293d795fde2d057e620b850ba63a18b189aa203fd319191a42f3940380d8c27762d1687413413df0bfc094d45c8e79d7dec7326c8a19278e4f61181646faa707a7531bb65c35f9f37a6a77ca5fbf63e55cae52a98fe059f2ecc8ace71f357940c54f6155bf72d1cb2cc89462922d94231bfc5d63ee4c8a31782e05972b1ce43b2580f40e02f0bb2cfaab98b1fc031fec291501e35f31986ce3ee752ef1ab0a2c4665581cd607dacf0033191150cb9c861037d4a859846d7768d30c31425d5b7295788ba0ad315a6908c281762c4c59bf6b1632f1f57d5efd2902a3a24cffcd0268a8b21b590224ee4835b8ccfd21a073424cfb0d93c3dbbdaba16c17f16e85b5067883ca52cea915c55a55c703005a5f2b3c777f8e13d9e3a043361d17cefd1ae7e6ed4d16183c3b481edfb46b374d3ee872f588091ca5febeb03414bfaa28e

###
# Functions to log messages in NASL scripts.
#
# @license
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# Revision: 1.17
#
# @remark
# Functions in this file should be used over the ones in ``spad_log_func.inc``
# to log messages in NASL scripts.
###

include("compat_shared.inc");
include("datetime.inc");
include("dump.inc");
include("spad_log_func.inc");

global_var ERROR_SUCCESS = 0x00000000;

namespace dbg
{

  global_var LOGNAME;
  global_var NS = 'dbg::';
  global_var CLI_MODE = isnull(get_preference("plugins_folder"));
  global_var TAP_MODE = FALSE;
  global_var _SCRATCH_PAD_MIRROR = [];

  global_var Error;

  global_var DBG_DEFAULT_TAB = '  ';
  global_var DBG_UNKNOWN_ERROR = 0xF0000000; # Hex code representing an unknown error.
  global_var DBG_LOG_INITIALIZED = 0; # Determines whether or not DBG_LOG_LEVEL has been initialized
  global_var DBG_LOG_LEVEL = 0; # The current level dictating the content and verbosity of logs
  global_var LOG_SETTINGS = [ # Settings for formatting logs by each log level
    { # Level 0: Debug Logging is disabled and no logs (except basic error logs) will be permitted
      "log_limit":-1, # Character limit of for logs
      "packet_limit": 0, # Character limit for packets (message characters excluded)
      "log_data":FALSE # Flag for if we allow logging of Dump data
    },
    { # Level 1: This is the base level for debug statements, and should reflect only basic details
      "log_limit":500,
      "packet_limit": 0,
      "log_data":FALSE
    },
    { # Level 2: This is the intermediate level and should reflect more advanced data
      "log_limit":1000,
      "packet_limit": 0,
      "log_data":FALSE
    },
    { # Level 3: Advanced Debug logging. Everything including dump data will be logged.
      "log_limit":1500,
      "packet_limit": 250,
      "log_data":TRUE
    },
    { # Level 4: Same as Level 3 but with NO log length limit
      "log_limit":-1,
      "packet_limit": -1,
      "log_data":TRUE
    }
  ];

  ##
  # Check if the given level is a valid log level.
  #
  # @param [lvl:integer] Log level we want to know the validity of.
  #
  # @return [boolean] TRUE/FALSE for if the given level is a valid log level.
  ##
  function is_valid_level(lvl)
  {
    if (empty_or_null(lvl))
      return FALSE;

    lvl = int(lvl);

    if (lvl < max_index(LOG_SETTINGS) && lvl > 0)
      return TRUE;

    return FALSE;
  }

  ##
  # Set default logname for calls to `dbg::log()`_ without ``name`` param.
  #
  # @param [force:boolean] Boolean to overwrite the logname if it's already set (optional, defaults to FALSE).
  ##
  function set_default_logname(force)
  {
    var fn = FUNCTION_NAME;
    if (!LOGNAME || force)
    {
      LOGNAME = _FCT_ANON_ARGS[0];
      log(src:fn, msg:"Set default log name to : " + LOGNAME);
    }
  }

  ##
  # Enables debug logs to the level set in the scan preferences or via `dbg::set_log_level()`_.
  #
  # @remark
  # This function sets the KB ``global_settings/enable_plugin_debugging`` to TRUE.
  ##
  function enable()
  {
    replace_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);
    DBG_LOG_INITIALIZED = 1;
    set_log_level();
  }

  ##
  # Disables possibility to log messages.
  #
  # @remark
  # This function removes the KB ``global_settings/enable_plugin_debugging``.
  ##
  function disable()
  {
    rm_kb_item(name:"global_settings/enable_plugin_debugging");
    set_log_level(0); # Set the log level to 0
  }

  ##
  # Checks if debug logging is enabled.
  #
  # @return [boolean] TRUE if debugging is enabled, FALSE otherwise.
  ##
  function is_enabled()
  {
    if (get_kb_item("global_settings/enable_plugin_debugging"))
      return TRUE;
    return FALSE;
  }

  ##
  # Sets the Debug log level determining how much to log.
  #
  # @remark
  # If debugging is not enabled, no change will be made.
  # Otherwise:
  #
  # - If a new level is provided -> set the level to that
  # - If no new level is provided, check if there's a level defined in the KB -> set the level to that
  # - If no new level is provided, and no level is in the KB -> set the level to 1 (the minimum for producing logs)
  #
  # NOTE: A KB value will only be looked for if No Int value was passed as an arg! If you provide an arg value
  # and the KB also has a value, the passed arg value will ALWAYS take precedence.
  #
  # @anonparam [new_level:integer] The level to set the log to (optional, defaults to the value in ``global_settings/debug_level``).
  #
  # @return [NULL] Always returns ``NULL`` even when debugging is not enabled.
  ##
  function set_log_level()
  {
    var new_level = _FCT_ANON_ARGS[0];

    # If debugging isn't enabled, default to level 0 (no logs)
    if (!is_enabled())
      return NULL;

    # If no level was provided, check for a value in the KB
    if (empty_or_null(new_level))
      new_level = get_kb_item("global_settings/debug_level");

    # If we have a valid value for new_level, update DBG_LOG_LEVEL to be new_level
    if (is_valid_level(lvl:new_level))
      DBG_LOG_LEVEL = new_level;
    else # default to the minimum log level that shows logs (1)
      DBG_LOG_LEVEL = 1;

    return NULL;
  }

  ##
  # General debugging template. Formats debugging message and forwards
  # to `spad_log()`_.
  #
  # @param [name:string] The log file in which the mesage should be logged.
  # @param [src:string]  The message source, e.g. "mssql_starttls" or "ssl_supported_ciphers.nasl".
  # @param [msg:string]  The message to log.
  # @param [ddata:data]  The data to dump to hex/ascii and append.
  #
  # @remark
  # The log name defaults to ``dbg::LOGNAME`` if nothing is given in ``name``.
  # If ``dbg::LOGNAME`` is also ``NULL``, `spad_log()`_ defaults to using ``(plugin filename - ext) + .log``.
  #
  # @return [NULL] Always returns ``NULL`` even when debugging is not enabled.
  ##
  function log(name, src, msg, ddata)
  {
    if (!is_enabled())
      return NULL;

    var time = "", out = "";

    # If we're running in CLI mode add timestamp
    if (CLI_MODE && !TAP_MODE)
    {
      time = strftime("[%F %T] ",unixtime());
      out += time;
    }

    # Add source, assume function if not nasl or nbin
    if (src)
    {
      out += src;
      var l = strlen(src);
      if (src !~ '\\.(nasl|nbin)$' && substr(src, l-2, l-1) != "()")
        out += "()";
      out += ": ";
    }

    # Add message
    out += msg;

    # Add ddata
    if (ddata)
    {
      out += '\n' + hexdump(ddata:ddata);
    }

    if (!name)
      name = LOGNAME;

    if (TAP_MODE)
      return out;

    spad_log(name:name, message:out);

    return NULL;
  }

  ##
  # Translates socket error code into description string.
  #
  # @anonparam [err:int] Error code returned from ``socket_get_error()``.
  #
  # @return [string] Description of the error.
  ##
  function soc_strerr()
  {
    var err = _FCT_ANON_ARGS[0];
    if (isnull(err)) return "error code missing";

    var e = int(err);
    if (e == NOERR) return "no error";
    if (e == ETIMEDOUT) return "operation timed out";
    if (e == ECONNRESET) return "connection reset by peer";
    if (e == EUNREACH) return "host unreachable";
    if (e == EUNKNOWN) return "unknown error";
    if (e == ESSL) return "SSL error";
    if (e == EINPROGRESS) return "operation in progress";
    if (e == ECONNREFUSED) return "connection refused";
    if (e == ENOBUFS) return "no buffer space available";

    return "unknown error code: "+err;
  }

  ##
  # Accepts a message to log with additional details, and accounts debug level.
  #
  # @param [lvl:int]              Debug level of the message to log.
  # @param [src:string]           Source function that's logging this info (optional).
  # @param [family:string]        Label of logging family associated with this info (optional).
  # @param [name:string]          Name of log to send this data to (optional, default behavior builds off plugin name)
  # @param [extra_name_list:list] List of additional log names to send this data to (optional).
  # @param [msg:string]           Message to be logged out.
  # @param [msg_details:array]    An array of additional details pertinent to the message being logged (optional).
  #
  # @remark
  # Format for msg_details:
  #
  # ``msg_details`` is an array where each key represents a particular "detail".
  # The value of those detail-keys is another array describing the detail's value
  # and the appopriate log level for the detail.
  # ```
  #  msg_details:{
  #   <Detail Name>: {"lvl":<Detail Level>, "value":<Detail Value>},
  #   etc...
  #  }
  # ```
  # Example:
  # ```
  #   msg_details:{
  #    "Connection Type": {"lvl":2, "value":"DCOM RPC"}
  #   }
  # ```
  # This example will result in the log output contain "Connection Type: DCOM RPC", and will only include it if
  # ``DBG_LOG_LEVEL`` is 2 or greater.
  # If ``DBG_LOG_LEVEL`` were 0 or 1, the output from the above example would omit "Connection Type" Detail.
  #
  # @return [NULL] It's important to know that the function returns NULL in
  #                case another functions returns this function's return value.
  ##
  function detailed_log(lvl, src, family, msg, msg_details, name, extra_name_list)
  {
    var output, details_output, detail_info, dump_data, source, logname, value;
    if (!DBG_LOG_INITIALIZED)
    {
      set_log_level();
      DBG_LOG_INITIALIZED = 1;
    }

    if (DBG_LOG_LEVEL == 0 || !is_enabled())
      return NULL;

    if (empty_or_null(lvl) || empty_or_null(msg))
      return NULL;

    # RES-142500 temporary suppression of SMB logs
    if (family == "SMB")
      return NULL;

    if (typeof(msg) != 'string') msg = string(msg);
    lvl = int(lvl);

    # If this message lvl is higher than the Debug Log Level, or if the the lvl is invalid
    if (lvl > DBG_LOG_LEVEL || !is_valid_level(lvl:lvl))
      return NULL;

    output = msg;

    # if a valid source function was provided, pre-pend it to the log
    if (!empty_or_null(src) && typeof(src) =~ '(data|string)')
      output = src+'(): '+output;

    output += format_details(msg_details:msg_details);

    output = trim_log(output); # Enforce the character limit appropriate for the current log level

    if (TAP_MODE)
      _SCRATCH_PAD_MIRROR[max_index(_SCRATCH_PAD_MIRROR)] = output;
    if (get_kb_item("TEST/is_test"))
      return output;

    foreach logname (extra_name_list)
    {
      if (!empty_or_null(logname)) log(msg:output, name:logname);
    }
    log(msg:output, name:name);

    return NULL;
  }

  ##
  # Wrapper that runs `dbg::detailed_log()`_ followed by a call to exit
  # to report exit messages to detailed log when needed.
  #
  # @param [src:string]           Source function that's logging this info (optional).
  # @param [name:string]          Name of log to send this data to (optional, default behavior builds off plugin name)
  # @param [family:string]        Label of logging family associated with this info (optional).
  # @param [extra_name_list:list] List of additional log names to send this data to (optional).
  # @param [msg:string]           Message to be logged out.
  # @param [msg_details:array]    An array of additional details pertinent to the message being logged (optional).
  #
  # @remark
  # If ``msg`` is not supplied `dbg::detailed_log()`_ will use ``exit_msg``.
  #
  # The value given in ``msg_details`` must follow the same structure as
  # the argument ``msg_details`` for `dbg::detailed_log()`_.
  #
  # @remark
  # This is Exiting. Debug level of the detailed log will be 1. This must always log.
  ##
  function detailed_log_and_exit(src, family, msg, msg_details, name, extra_name_list, exit_level, exit_msg)
  {
    # Check for no exit_msg
    if (isnull(exit_msg))
      exit_msg = "NO AUDIT TRAIL MESSAGE SUPPLIED!";

    if (isnull(exit_level))
      exit_level = 0;

    # Log
    if (empty_or_null(msg))
      detailed_log(lvl:1, src:src, family:family, msg:exit_msg, msg_details:msg_details, name:name, extra_name_list:extra_name_list);
    else
      detailed_log(lvl:1, src:src, family:family, msg:msg, msg_details:msg_details, name:name, extra_name_list:extra_name_list);

    # "Exit"
    if (get_kb_item("TEST/is_test"))
      return exit_msg;
    else
      exit(exit_level, exit_msg);
  }

  ##
  # Build a packet array to be used by `dbg::log_packets()`_ given a debug message and packet data.
  #
  # @param [list:list reference] The list to which the packet array should be appended (optional).
  # @param [msg:string] The debug message to print before printing the packet data.
  # @param [data:data] The raw packet data to log.
  #
  # @return [array|NULL] The built package array to be given to `dbg::log_packets()`_, or NULL if an error occurred.
  #
  # @remark
  # If a list is given in ``list`` then the function will return NULL and append the
  # packet array to the list.
  ##
  function add_packet_log(&list, msg, data)
  {
    if (empty_or_null(msg) || empty_or_null(data))
    {
      dbg::detailed_log(src:FUNCTION_NAME, lvl:1, msg:'Missing a required argument.');
      return NULL;
    }

    var packet = {
      "msg":msg,
      "data":data
    };

    # If we're given a list append the packet array to the list
    if (!isnull(list))
    {
      if (!is_list(list))
      {
        dbg::detailed_log(src:FUNCTION_NAME, lvl:1, msg:'Argument "list" is not a list, it has to be.');
        return NULL;
      }
      append_element(var:list, value:packet);
      return NULL;
    }

    # If we don't have any list then return the formatted packet array
    return [packet];
  }

  ##
  # Appropriately logs the list of given packets following their order in said list.
  #
  # @param [name:string]          The name of the log file in which to send the log
  #                               (optional, default to plugin script name).
  # @param [src:string]           The name of the function/script logging the packets (optional).
  # @param [packets:list]         A list of arrays containing the debug message and data to log.
  #
  # @param [reverse:boolean]      Boolean to set to TRUE to log the packets in the
  #                               inverted order of ``packets``. (optional, defaults to FALSE).
  #
  # @param [max_level:boolean]    Boolean to set to TRUE to only report the packets when an unlimited
  #                               amount of characters is allowed by the log level. (optional, default to FALSE).
  #
  # @param [extra_name_list:list] List of additional log names to send the data to (optional).
  #
  # @return [NULL] This function should always return NULL in case another function calls it as its return value.
  #
  # @remark
  # The value given in ``packets`` should be a list of arrays built with `dbg::add_packet_log()`_.
  #
  # @remark
  # The order of the arrays in ``packets`` should match their chronological order.
  # I.e. the last packet that arrived/was parsed should be the last in the list.
  # This is important so that the function can print only the most imporant packet
  # if the debug level doesn't allow for all packets to be logged. In theory the function
  # assumes the last packet is the most important one (or the first one if ``reverse`` is TRUE).
  ##
  function log_packets(name, src, packets, reverse, max_level, extra_name_list)
  {
    if (empty_or_null(packets))
      return NULL;

    if (typeof_ex(packets) != 'list')
    {
      detailed_log(lvl:1, src:FUNCTION_NAME, msg:"Argument 'packets' must be a list of arrays.");
      return NULL;
    }

    if (!DBG_LOG_INITIALIZED)
    {
      set_log_level();
      DBG_LOG_INITIALIZED = 1;
    }

    var unlimited = FALSE;
    if (LOG_SETTINGS[DBG_LOG_LEVEL].packet_limit < 0)
      unlimited = TRUE;

    if (max_level && !unlimited)
      return NULL;

    if (!LOG_SETTINGS[DBG_LOG_LEVEL].log_data || !LOG_SETTINGS[DBG_LOG_LEVEL].packet_limit)
      return NULL;

    var len, i, index, msg_detail;
    len = max_index(packets);
    if (!len)
      return NULL;

    # Remove packets which don't have any data so that it only shows the non-empty packets
    var cleaned_packets = [];
    for (i=0; i<len; i++)
    {
      # For effciency, also reverse the order in this loop if necessary
      if (reverse && !unlimited)
        index = len-1-i;
      else
        index = i;
      if(empty_or_null(packets[index].data))
        continue;
      cleaned_packets[i] = packets[index];
    }
    packets = NULL;
    len = max_index(cleaned_packets);

    if (unlimited)
    {
      for (i=0; i<len; i++)
      {
        msg_detail = {"Data":{"lvl":DBG_LOG_LEVEL, "value":cleaned_packets[i].data}};
        if (cleaned_packets[i].data == 'REDACTED')
        {
          msg_detail = NULL;
          cleaned_packets[i].msg += '\n[REDACTED]';
        }
        detailed_log(
          name:name,
          extra_name_list:extra_name_list,
          src:src,
          lvl:DBG_LOG_LEVEL,
          msg:cleaned_packets[i].msg,
          msg_details:msg_detail);
      }
      return NULL;
    }

    if (strlen(cleaned_packets[len-1].data) > LOG_SETTINGS[DBG_LOG_LEVEL].packet_limit)
      msg_detail = {"Warn": {"lvl": DBG_LOG_LEVEL, "value": "The packet is too big to be displayed at debug level " + DBG_LOG_LEVEL}};
    else
      msg_detail = {"Data": {"lvl": DBG_LOG_LEVEL, "value": cleaned_packets[len-1].data}};

    if (cleaned_packets[len-1].data == 'REDACTED')
    {
      msg_detail = NULL;
      cleaned_packets[len-1].msg += '\n[REDACTED]';
    }

    detailed_log(
      name:name,
      extra_name_list:extra_name_list,
      src:src,
      lvl:DBG_LOG_LEVEL,
      msg:cleaned_packets[len-1].msg,
      msg_details:msg_detail);

    return NULL;
  }

  ##
  # Check if the message to log is longer than the max allowed length, and truncate if necessary.
  #
  # @anonparam [msg:string] Message to check and trim.
  #
  # @return [string] Log Length compliant message.
  ##
  function trim_log()
  {
    var msg = _FCT_ANON_ARGS[0];
    var msg_length; # Total character length of the raw message
    var msg_shown; # Total character length of the messsage to actually be logged out (shown)
    var char_limit = LOG_SETTINGS[DBG_LOG_LEVEL].log_limit; #Total number of characters to limit the log to

    # The log_length value for the current debug level is < 0, that means we won't enforce a limit
    if (empty_or_null(msg) || empty_or_null(char_limit) || char_limit < 0)
      return msg;

    msg = string(msg);
    msg_length = strlen(msg);
    msg_shown = msg_length;

    # if the message length would exceed the max...
    if (msg_length > char_limit)
      msg = substr(msg, 0, char_limit) + '...\n  ('+char_limit+'/'+msg_length+' bytes shown)';

    return msg;
  }

  ##
  # Transforms the given object into a string and formats it for logging.
  #
  # @param [obj:any]     The object to transform and format for logging.
  # @param [tab:integer] The number of tabs to prepend to all lines of the formatted string (optional, defaults to 0).
  #
  # @return [string] A formatted string representing the object given in ``obj``.
  ##
  function format_object(obj, tab)
  {
    var formatted_data = '';

    if (isnull(tab) || typeof(tab) != 'int')
      tab = 0;

    formatted_data = obj_rep(obj, depth:tab + 1, indent:DBG_DEFAULT_TAB, prettify:TRUE);

    return formatted_data;
  }

  ##
  # Creates the details string for a log, from the array containing the details.
  #
  # @param [msg_details:array]  The Details Array from which the details log should be created.
  # @param [tab:integer]        The number of tabs to prepend before all lines of the log (optional, defaults to 1).
  # @param [ignore_lvl:boolean] Flag to bypass the log level restriction on data dumps (optional, defaults to FALSE).
  #
  # @return [string] The log message constructed from the Details Array. The string can be empty.
  ##
  function format_details(msg_details, tab, ignore_lvl)
  {
    var indent, indent_plus, len;
    var dump_data, detail_info, value, type;
    var details_output = '';
    var output = '';

    if (empty_or_null(msg_details) || typeof_ex(msg_details) != 'array')
      return output;

    if (isnull(tab) || typeof(tab) != 'int')
      tab = 1;

    if (isnull(ignore_lvl))
      ignore_lvl = FALSE;

    len = len(DBG_DEFAULT_TAB);
    indent = crap(data:DBG_DEFAULT_TAB, length:tab * len);
    indent_plus = indent + DBG_DEFAULT_TAB;

    for (var detail in msg_details)
    {
      if (empty_or_null(msg_details[detail]) || typeof_ex(msg_details[detail]) != 'array' || # Detail is an actual array
          empty_or_null(msg_details[detail].lvl) || !is_valid_level(lvl:msg_details[detail].lvl) || # has a valid lvl value
          (msg_details[detail].lvl > DBG_LOG_LEVEL && !ignore_lvl) || isnull(msg_details[detail].value)) # Has a valid value and is appropriate for this log level
      {
        continue;
      }

      # Details named Data are special and hold info in raw hex
      if (detail == 'Data')
      {
        if (LOG_SETTINGS[DBG_LOG_LEVEL].log_data || ignore_lvl)
        {
          dump_data = hexdump(ddata:msg_details[detail].value);
          dump_data = str_replace(string:dump_data, find:'0x', replace:indent_plus + '0x');
        }
        continue;
      }

      # Format the value depending on its type
      type = typeof(msg_details[detail].value);
      if (type == 'array')
        detail_info = format_object(obj:msg_details[detail].value, tab:tab + 1);
      else if (type !~ '(data|string)')
        detail_info = format_object(obj:msg_details[detail].value);
      else
        detail_info = msg_details[detail].value;

      if (!empty_or_null(detail_info))
        details_output += '\n' + indent_plus + detail + ': ' + detail_info;
    }

    if (!empty_or_null(details_output))
      output += '\n' + indent + 'DETAILS:' + details_output + '\n';

    if (!empty_or_null(dump_data))
      output += '\n' + indent + 'DATA:\n' + dump_data + '\n';

    return output;
  }

  ##
  # Determines if the given value is an Error.
  #
  # @anonparam [1st:any] The value to inspect.
  #
  # @return [boolean] TRUE if the value is an Error, FALSE otherwise.
  #
  # @remark
  # This function is meant to help catch an error thrown with `dbg::raise_error()`_.
  #
  # A function can raise an error by returning the return value of `dbg::raise_error()`_.
  # Then, the function receiving that value **must** check if it's an error with `dbg::is_error()`_,
  #
  # If the return value is indeed an error, i.e. `dbg::is_error()`_ returned TRUE, then either the 
  # error should be logged with `dbg::log_error()`_ or be cleared with `dbg::clear_error()`_ if the error is benign.
  ##
  function is_error()
  {
    if (typeof_ex(_FCT_ANON_ARGS[0]) != 'dbg::Error')
      return FALSE;

    return TRUE;
  }

  ##
  # Removes traces of error and deletes the global Error object instance.
  #
  # @param [reset:boolean] A flag to set to TRUE to completely clear any trace of the error.
  #
  # @remark
  # ``reset`` should only be ever set to TRUE if the error that was previously logged
  # is considered benign and did not hinder the script's logic.
  #
  # That's because setting reset to TRUE will remove all traces of the error ever being logged
  # if it wasn't logged with `dbg::log_error()`_ before being cleared.
  #
  # Note however that `dbg::log_error()`_ will automatically clear the error trace from memory
  # and so `dbg::clear_error()`_ should **not** be called after `dbg::log_error()`_ unless absolutely necessary.
  ##
  function clear_error(reset)
  {
    if (!is_error(Error))
      return NULL;

    if (isnull(reset))
      reset = FALSE;

    Error.clear(reset:reset);
    delete(Error);
  }

  ##
  # Creates and returns an Error object that a calling function can catch with `dbg::is_error()`_
  # and then log the error trace in memory with `dbg::log_error()`_.
  #
  # @remark
  # See the ``dbg::Error`` object for more information on how to interact with an Error.
  #
  # @param [src:string]    Source function (ie: the function the error occured in) (optional).
  # @param [family:string] Label of logging family associated with this info (optional, only used to disable SMB logs).
  # @param [code:integer]  Integer error code corrosponding to the error being logged (optional).
  # @param [name:string]   Human Readable name of the error being logged (optional).
  # @param [msg:string]    Text Description of the error that occured (optional).
  # @param [details:array] An array of additional details pertinent to the error being logged (optional).
  #
  # @return [object] The `dbg::Error`_ object to catch with `dbg::is_error()`_.
  #
  # @remark
  # The array given in ``details`` **must** follow the same structure as the ones given in 
  # ``msg_details`` of `dbg::detailed_log()`_.
  ##
  function raise_error(src, family, code, name, msg, details)
  {
    if (family == 'SMB')
      return NULL;

    if (!is_error(Error))
      Error = new dbg::Error();

    Error.add_error(src:src, code:code, name:name, msg:msg, details:details);

    return Error;
  }

  ##
  # Logs the error trace retained in memory after calling `dbg::raise_error()`_.
  #
  # @param [msg:string] Text Description of the results of the error (optional).
  #
  # @return [NULL] The return value of `dbg::Error.report_error()`_.
  #
  # @remark
  # After calling this function the error trace in memory is automatically cleared.
  ##
  function log_error(msg)
  {
    if (!is_error(Error))
      Error = new dbg::Error();

    return Error.report_error(msg:msg);
  }

  # TODO: This needs to be an object so that if it was initialized and "Log on error only" is enabled
  # it will push the temp log scratchpad to the long-lived table.
  object Error
  {
    var error_trace = [];
    var ignore_lvl = FALSE;
    var err_kb = 'Error/' + SCRIPT_NAME;

    ##
    # Constructor for the Error object.
    #
    # @anonparam [ignore_lvl:boolean] Flag to ignore logging levels when logging errors (optional, defaults to FALSE).
    # @anonparam [err_kb:string]      KB item to set to TRUE when initializing the object to keep track of
    #                                 plugins raising errors (optional, defaults to ``Error/<SCRIPT_NAME>``).
    ##
    function Error()
    {
      if (!DBG_LOG_INITIALIZED)
      {
        set_log_level();
        DBG_LOG_INITIALIZED = 1;
      }

      if (!empty_or_null(_FCT_ANON_ARGS[1]))
        this.err_kb = _FCT_ANON_ARGS[1];
      # Set KB item so that the error summary plugin reports the plugin running.
      replace_kb_item(name:this.err_kb, value:TRUE);

      if (_FCT_ANON_ARGS[0])
        this.ignore_lvl = TRUE;
    }

    ##
    # Adds an error to the trace.
    #
    # @param [src:string]    The name of the function in which the error occurred (optional).
    # @param [code:integer]  An integer code representing the error (optional).
    # @param [name:string]   The technical name of the error, e.g. ``ERROR_SSH_INVALID_MAC`` (optional).
    # @param [msg:string]    A succinct sentence describing the error (optional).
    # @param [details:array] An array containing more information about the error (optional).
    #
    # @remark
    # The array given in ``details`` must have the same structure as the ones
    # given in ``msg_details`` of `dbg::detailed_log()`_ (see that function's documentation).
    ##
    public function add_error(src, code, name, msg, details)
    {
      var error_data = {};

      # This function appends an Error Data Array to the error trace list in the object.
      # That array has the following structure.
      #
      # Error Data Array:
      # {
      #   Code:         <Integer error code>,
      #   Name:         <String Name of the Error>,
      #   Description:  <Description of the Error>,
      #   Function:     <String name of the function the Error occurred in>,
      #   Details:      <Array of additional details pertinent to the Error>
      # }

      # If we don't have a source function that's okay! We'll set it to NULL and not worry about it
      if (empty_or_null(src) || typeof(src) !~ 'string|data')
        src = NULL;

      # Assign defaults if we have missing or bad parameters
      if (empty_or_null(code) || typeof(code) != 'int')
        code = DBG_UNKNOWN_ERROR;

      if (empty_or_null(name) || typeof(name) !~ 'string|data')
      {
        if (code == DBG_UNKNOWN_ERROR) # If we also weren't given a valid error code, then defautl the name to be DBG_UNKNOWN
          name = "DBG_UNKNOWN_ERROR";
        else # Otherwise, if we did get a code, it's okay if don't have a name
          name = NULL;
      }

      # msg/Description always defaults to Unknown Error
      if (empty_or_null(msg) || typeof(msg) !~ 'string|data')
      {
        if (code == DBG_UNKNOWN_ERROR && name == 'DBG_UNKNOWN_ERROR') # if we didn't get a code or a name, default the description
          msg = "An Unknown Error occured";
        else # Otherwise if were given a name or a code, but not a description, it's okay to not have one
          msg = NULL;
      }

      # If we were given additional details, save them
      if (!empty_or_null(details) && typeof_ex(details) == 'array')
        error_data["Details"] = details;

      # Store everything in an array
      error_data["Function"] = src;
      error_data["Name"] = name;
      error_data["Description"] = msg;
      error_data["Code"] = code;

      # And add the array to the trace
      append_element(var:error_trace, value:error_data);
    }

    ##
    # Logs the trace the object has in memory.
    #
    # @param [msg:string] A message introducing the trace.
    #
    # @return [NULL] The return value of `dbg::log()`_.
    ##
    public function report_error(msg)
    {
      var output, trace_len, tab;
      output = "[ERROR] An unspecified error has occured";

      if (!empty_or_null(msg) && typeof(msg) =~ 'string|data')
        output = "[ERROR] " + msg;

      # If no errors were added to the trace
      if (empty_or_null(error_trace))
      {
        output += '\n  DETAILS:\n    Error: An Error occurred, but no info was provided';
        return log(msg:output);
      }

      trace_len = max_index(error_trace);
      tab = DBG_DEFAULT_TAB;
      for (var i = trace_len - 1; i >= 0; i--)
      {
        if (empty_or_null(error_trace[i]))
          continue;

        if (i == 0)
          output += '\n' + tab + '[ROOT]';
        else if (i == trace_len - 1)
          output += '\n' + tab + '[TOP ]';
        else
          output += '\n' + tab + '   -> ';

        output += get_log_msg(index:i);

        if (empty_or_null(error_trace[i]['Details']))
          continue;

        output += format_details(msg_details:error_trace[i]["Details"], tab:4, ignore_lvl:this.ignore_lvl);
      }

      clear();
      return log(msg:output);
    }

    ##
    # Constructs the log message representing the error at the given index in the trace.
    #
    # @param [index:integer] The index in the trace for which to construct the message
    #                        (optional, defaults to the maximum index).
    #
    # @return [string|NULL] The message for the error, or NULL if there is no error at the given index.
    ##
    public function get_log_msg(index)
    {
      var log_msg;
      var max_i = max_index(error_trace) - 1;
      if (isnull(index))
        index = max_i;

      if (index > max_i || index < 0)
        return NULL;

      if (empty_or_null(error_trace[index]))
        return NULL;

      if (error_trace[index]["Code"] == DBG_UNKNOWN_ERROR)
        log_msg = 'ERROR';
      else
        log_msg = '0x'+int2hex(num:error_trace[index]["Code"]);

      if (!isnull(error_trace[index]["Name"]))
        log_msg += ': ' + error_trace[index]["Name"];

      log_msg = '[' + log_msg + ']';

      if (!isnull(error_trace[index]["Description"]))
        log_msg += ' ' + error_trace[index]["Description"];

      if (!isnull(error_trace[index]["Function"]))
        log_msg = '[' + error_trace[index]["Function"] + '()]' + log_msg;

      return log_msg;
    }

    ##
    # Gets the last error code from the trace.
    #
    # @return [integer] The error code of the last error added to the trace.
    #
    # @return [integer] The error code of the last error in the trace.
    #
    # @remark
    # If no code was given when the error was added to the trace then the value
    # of ``dbg::DBG_UNKNOWN_ERROR`` will be returned.
    ##
    public function get_last_code()
    {
      if (empty_or_null(error_trace))
        return NULL;

      return error_trace[max_index(error_trace) - 1]["Code"];
    }

    ##
    # Clears the error trace.
    #
    # @param [reset:boolean] Flag to also clear the error flag from the KB (optional, defaults to FALSE).
    #
    # @remark
    # ``reset`` should only be set to TRUE if the error is benign and does not
    # hinder the logic of the code that encountered the error.
    ##
    public function clear(reset)
    {
      error_trace = [];
      if (reset)
        rm_kb_item(name:err_kb);
    }
  }
}
