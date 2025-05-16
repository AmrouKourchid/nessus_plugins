#TRUSTED 61d039522165b823fa26ff2bf78437465b7e24ecb2a6c77af85273a93f28a94f4154f06b8aea3ce3cc0c12f8372091e18e65c344ce101af12b044144f923771a2309cec6f2e4daa8ee13f306e4f0a8d0681d72b98dffcdce00f3e9a924c84a8b9cca011d9d2698d69df1e97c5dd2b2774376196b4125d1ee6f69dbae9bf27ad887867f936c7236e55df71c3bf5de5341d4fa3e282853c0ea60181b46b20288748754a1324624ca90cde6f6a1518699c8cc5fd004e18f334c0b8b200e7b6e361ffd7e3e1dd554f11ccb5be3aa9f28a6fc41d81891496beb13932fc1e7ceec9ef072b3b2b679258ce46efc34f30af037d55e007d48f8d0b9b9704770d1704d7d6064a175152df0405d6b2cfef56c15024f393a3c168604d399ae6be5ed7be67e0107272654f48009ee7dd614abb45be99fd43099210b9821a16508601894d0572dd2a82d022e2c800d85be826e6c3bb54441290f79d71d8ec257f614972b744aff1ff7b74bed5e8c9f2198e5be5c910dae4c2e1b7b30220e7b866dc26f825af6bdfce178c540bcb9363e4a083744706e850b61dccf5cfe1ffea9773ad6334a390ba1faa63fb25e89fd50cfc1d6f1b2e274ecb092a886d489c6bcdd1fe5756fca55ef1d1fbaaad8b1685081fc569545de5b86143094b7e8e371b33e5be2233ba935a4ad25e0edc0b9e48fdbe4824ebd8aedc177168576ffaade954fbfd609924204
#TRUST-RSA-SHA256 3893583f00582df70ad3cf019681a02e0792e535f65814286b7d1b7b1479013f0ac5f93ecb569a37a253df9414c3ebee50388f42d60bd33fd5eb64d93e42afb1a260e82105bae96a0b04e1b94c31442dea694e31a00880c950a3b27fd99174a93209a8020dbc5d3f909c38d4dbce805a2ff5a4d728e8baac14d7de0c199fdf6a94db7cdeb8a74a70eff8dd024035063f324fd284eec515213db42d7ae5949f6b54971f3bdcc5dddc98086215564f2924bc89418d44dbcfefff701db684c1c726e8f93f8113cfd8f5d53f431da65db7339938bf57eaca8234843b9315ab7e4178a0200d49bde80e90de9622e2a4468df7c26de6d627e3fe6ddda40733fe7cab914358319b5d3ed285c8c361fcfe2d1e3fcb4f801bb5f3e55865ae4641b56d5e0a37d7669b1047205975df9828d93f50570d4a935765a55686ecd12f504cb9bd4d5e7b1d0a3b40b2d42a46f6c380077b2ea79f071eae454f1463cb30fdbd70284659a12bca9c4424f5713e953bd9618519601a4125bee842c1925df2695446f25dd6527ca89cf8acf8148b431c6c23f9f26b97c243bd6e490ea23a4a9d215a43ec5a8039a7b60027f8664f797877dd07974379e89787a95c3eef341eee9422ded2956c2b8e87b488fc347173fea158ef9e769f2eec3dd146a88362433975110d9275cf2043bbbb6ff96ebe7488a0de2fa9a15ae79ef6398f65a5583a89b42799d9

###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# supersedence_builder.inc
#
# Revision: 1.3
#
###

include('compat_shared.inc');
include('debug.inc');
include('spad_log_func.inc');

namespace supersedence
{
  # Define types of supersedence patch data
  var patch_types = make_array('MSKB', 0);

  # Define supersendence data gathering functions
  var patch_data_functions = make_array('MSKB', @supersedence::gather_and_store_by_type_from_scratchpad);

  # Define functions to determine if patch type is availble
  var patch_type_available = make_array('MSKB', @supersedence::mskb_available);

  # Track if supersedence data tables have been created.
  var scratchpad_table_created = false;
  var report_db_table_created = false;

  # Scratchpad table name for supersedence data
  var scratchpad_table_name = 'supersedence_data';

  # Report DB table name for supersedence data
  var report_db_table_name = 'supersedence_data';

  # Supersedence log name.
  var log_name = 'supersedence_data_builder.log';

  ##
  # Obtain the plugin id from a plugin filename (SCRIPT_NAME) value
  #
  # @param [filename:string] SCRIPT_NAME value for the plugin you want to get the ID for
  # @param [plugin_id:reference] pointer to variable that will set the plugin_id
  #
  # @return 1 on success, Fail states return NULL if none found or a number larger than 1 if multiple hits
  ##
  function get_plugin_id(filename, &plugin_id)
  {
    if (isnull(filename)) return NULL;

    if (!report_db_table_exists(table: 'Plugins'))
    {
      dbg::detailed_log(
        name: supersedence::log_name,
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Plugins table doesn't exist. Can't lookup plugin ID for filename",
        msg_details: {
          "filename": {"lvl": 1, "value": filename}});
      return NULL;
    }

    var plugin_data = query_report('SELECT id FROM Plugins WHERE plugin_fname LIKE "%'+filename+'%"');
    var id_cnt = max_index(plugin_data);
    if (id_cnt == 1)
    {
      plugin_id = plugin_data[0]['id'];
      return 1;
    }
    else
    {
      return id_cnt;
    }
  }

  ##
  # Obtain the host ID from host IP.
  #
  # @param [host_ip:string] Host IP to look up. Defaults to value of ``get_host_ip()``.
  #
  # @return Host ID on success and NULL on failure.
  ##
  function get_host_id(host_ip)
  {
    if (isnull(host_ip)) get_host_ip();

    if (!report_db_table_exists(table: 'Host'))
    {
      dbg::detailed_log(
        name: supersedence::log_name,
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Host table doesn't exist. Can't lookup host ID for IP.",
        msg_details: {
          "IP": {"lvl": 1, "value": host_ip}});
      return NULL;
    }

    var host_id = query_report('SELECT id FROM Host WHERE host_ip = ?', host_ip);

    if (max_index(host_id) == 1)
    {
      host_id = host_id[0]['id'];
    }
    else
    {
      host_id = NULL;
      dbg::detailed_log(
        name: log_name,
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Unable to determine Host ID for host IP",
        msg_details: {
          "IP": {"lvl": 1, "value": host_ip}});
    }

    return host_id;
  }

  ##
  # Check if table exists in scratchpad.
  #
  # @param [table:string] Table to check existance of.
  #
  # @return [boolean] true if exists and false if it doesn't.
  ##
  function scratchpad_table_exists(table)
  {
    if (isnull(table)) return false;

    var exists = query_scratchpad('SELECT name FROM sqlite_master WHERE type = \'table\' AND name = ?', table);
    return (!isnull(exists) && !isnull(exists[0]));
  }

  ##
  # Check if table exists in report db.
  #
  # @param [table:string] Table to check existance of.
  #
  # @return [boolean] true if exists and false if it doesn't.
  ##
  function report_db_table_exists(table)
  {
    if (isnull(table)) return false;

    var exists = query_report('SELECT name FROM sqlite_master WHERE type = \'table\' AND name = ?', table);
    return (!isnull(exists) && !isnull(exists[0]));
  }
 
  ##
  # Create the scratchpad supersedence table
  ## 
  function scratchpad_create_table()
  {
    # id - Primary key
    # host - Associated host IP
    # plugin_name - Associated plugin name
    # type - Patch type
    # data - JSON representing patch data. Varies by patch type.
    query_scratchpad('CREATE TABLE IF NOT EXISTS ' + supersedence::scratchpad_table_name + ' (id INTEGER PRIMARY KEY, host TEXT, plugin_name TEXT, type TEXT, data TEXT)');
    supersedence::scratchpad_table_created = true;
  }

  ##
  # Create the report db supersedence table
  ## 
  function report_db_create_table()
  {
    # id - Primary key
    # host - Associated host ID
    # plugin_id - Associated plugin ID
    # type - Patch type
    # data - JSON representing patch data. Varies by patch type.
    query_report('CREATE TABLE IF NOT EXISTS ' + supersedence::report_db_table_name + ' (id INTEGER PRIMARY KEY, host TEXT, plugin_id TEXT, type TEXT, data TEXT)');
    supersedence::report_db_table_created = true;
  }

  ##
  # Store supersedence data in scratchpad.
  #
  # @param [plugin_name:string] filename (SCRIPT_NAME) of plugin.
  # @param [host_ip:string] IP of host. Defaults to value of get_host_ip();
  # @param [type:string] String identifier for patch type.
  # @param [data:any] data to be stored.
  # @param [do_serialization:boolean] Specifies if serialization should be performed on data. Defaults to true.
  #
  # @return true on successful parameters and false on failed parameters
  ##
  function scratchpad_insert_data(plugin_name, host_ip, type, data, do_serialization)
  {
    if (isnull(supersedence::patch_types[type])) return false;
    if (isnull(plugin_name)) plugin_name = SCRIPT_NAME;
    if (isnull(host_ip)) host_ip = get_host_ip();
    if (isnull(do_serialization)) do_serialization = true;

    var serialized_data;
    if (do_serialization)
    {
      serialized_data = serialize(data);
    }
    else
    {
      serialized_data = data;
    }

    if (!supersedence::scratchpad_table_created) supersedence::scratchpad_create_table();
    query_scratchpad('INSERT INTO ' + supersedence::scratchpad_table_name + ' (host, plugin_name, type, data) VALUES (?,?,?,?)', host_ip, plugin_name, supersedence::patch_types[type], serialized_data);

    return true;
  }

  ##
  # Store supersedence data in report db.
  #
  # @param [plugin_name:string] filename (SCRIPT_NAME) of plugin.
  # @param [host_ip:string] IP of host.
  # @param [type:string] String identifier for patch type.
  # @param [data:any] data to be stored.
  # @param [do_serialization:boolean] Specifies if serialization should be performed on data. Defaults to true.
  #
  # @return true on successful parameters and false on failed parameters
  ##
  function report_db_insert_data(plugin_name, host_ip, type, data, do_serialization)
  {
    if (isnull(supersedence::patch_types[type])) return false;
    if (isnull(do_serialization)) do_serialization = true;
    if (isnull(host_ip))
    {
      dbg::detailed_log(lvl: 1, name:log_name, src: FUNCTION_NAME, msg: "host_ip is NULL.");
      return false;
    }
    if (isnull(plugin_name))
    {
      dbg::detailed_log(lvl: 1, name:log_name, src: FUNCTION_NAME, msg: "plugin_name is NULL.");
      return false;
    }

    var plugin_id = NULL;
    var id_cnt = supersedence::get_plugin_id(filename:plugin_name, plugin_id:plugin_id);
    if (isnull(id_cnt))
    {
      dbg::detailed_log(
        name: log_name,
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Unable to find plugin id for plugin_name",
        msg_details: {
          "plugin_name": {"lvl": 1, "value": plugin_name}});
      return false;
    }
    else if (id_cnt != 1)
    {
      dbg::detailed_log(
        name: log_name,
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Found multiple plugin id entries for plugin_name.",
        msg_details: {
          "plugin_name": {"lvl": 1, "value": plugin_name},
          "Count": {"lvl": 1, "value": string(id_cnt)}});
      return false;
    }

    var host_id = supersedence::get_host_id(host_ip: host_ip);

    if (isnull(host_id))
    {
      return false;
    }

    var serialized_data;
    if (do_serialization)
    {
      serialized_data = serialize(data);
    }
    else
    {
      serialized_data = data;
    }

    if (!supersedence::report_db_table_created) supersedence::report_db_create_table();
    query_report('INSERT INTO ' + supersedence::report_db_table_name + ' (host, plugin_id, type, data) VALUES (?,?,?,?)', host_id, plugin_id, supersedence::patch_types[type], serialized_data);

    return true;
  }

  # Supersedence patch data gathering functions

  ##
  # Generalized patch type data gathering function. Used for transfering data from scratchpad into the report db.
  # This is useful for patch types that require storing supersedence data in to scratchpad during the scan to be
  # processed at the end.
  #
  # @param [type:string] String identifier for patch type.
  #
  # @return [integer] Count of entries stored for patch type into report db.
  ##
  function gather_and_store_by_type_from_scratchpad(type)
  {
    var cnt = 0;

    if (isnull(type) || isnull(supersedence::patch_types[type]))
    {
      dbg::detailed_log(
        name: log_name,
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Invalid type.",
        msg_details: {
          "type": {"lvl": 1, "value": type}});
      return cnt;
    }

    if (!scratchpad_table_exists(table: supersedence::scratchpad_table_name))
    {
      dbg::detailed_log(
        name: log_name,
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Scratchpad table not found.",
        msg_details: {
          "Table name": {"lvl":1, "value":supersedence::scratchpad_table_name}});
      return cnt;
    }

    var entries = query_scratchpad('SELECT * FROM ' + supersedence::scratchpad_table_name + ' WHERE type = ?', supersedence::patch_types[type]);
    if (!isnull(entries))
    {
      dbg::detailed_log(
        name: log_name,
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "Number of found supersedence data entries.",
        msg_details: {
          "Number": {"lvl": 2, "value": max_index(entries)}});
      var ret = false;
      foreach var entry (entries)
      {
        ret = supersedence::report_db_insert_data(host_ip:entry['host'], plugin_name:entry['plugin_name'], type:type, data:entry['data'], do_serialization: false);
        if(ret) cnt++;
      }
    }
    
    return cnt;
  }

  # Patch type availability functions

  ##
  # Determine if at least one patch type is available.
  #
  # @return [boolean] TRUE if at least one is available and FALSE if not
  ##
  function any_patch_types_available()
  {
    foreach var is_available (patch_type_available)
    {
      if (is_available()) return TRUE;
    }

    return FALSE;
  }

  ##
  # Determine if MSKB patch type data is available.
  #
  # @return [boolean] TRUE if available and FALSE if not
  ##
  function mskb_available()
  {
    if (get_kb_item('SMB/MS_Bulletin_Checks/Possible')) return TRUE;
    
    return FALSE;
  }
}
