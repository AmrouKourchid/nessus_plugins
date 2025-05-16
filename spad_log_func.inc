#TRUSTED 75f4b3d17c3e02ac2773eae3e1d9b910b12016f0f4d4f560349dd4cd14319298ef363f133f436029d6b4022eb6c197c259194eb4c00fdd52d06435162b3ace64aff32817c0fb745249caa56f6edb10571d13234f82380f74b178300d07fa70d03240960f683f3b585b85b4c8b59ad75e39355cf7d423fb1bc7d107f487a3ec6ad4996e4d1bfcb154dccef8c9aa847471f072399aff65bb757b8bd6032f95543ed9dc724650b483c81bc28119bf5374a4d03b4a69887087c663e6ca1a644539b82ddf99f487acc509b2682f4f2bfaf675e7d844dd1f41ffa9a063776c70d415adf3b0af96de9ecb8941046777c1945dfb53978d6348fbf8e0f1271b79814b4dda359ee3fd8b7978cf9f3d6dd03f48ad7e106831f825e9857c215345d0234e33dbe73755ac8156c7737c2c3989875c2bdfd531a53379a301318071b9936aa0a8308ab3dd923f94c0f579d6083cd981f2b1d4da4fb10bafcc08a1c4d196738c5c7383eeff432a7d84537a7e0f8e03c9ba860cebcd53c303caa21dc63932af03ce8e58cfe4552c6005d9179497beba67010875f0afb67a7af0e8730dd5bcec366248befe293896cdee8c59c08d2a47edcab353fd66ee6068a6c185fece03224ad8932803d9e2f07a5b48dcb73fce3e495c17c95d956fa506b5826c753681b5b9a9bcfcd115349400f6667046dac02c11dd2d75191cf00d0200be12115a4bc2bb0883
#TRUST-RSA-SHA256 aca683f4a0de9504ff29881754721e33057314ce75c18630dc429293bce7c3a8fdcf103a133109e28d266daaaa59001b38d521a18fe7147284fd3e32f765f2dbcaa9daa49bd700ce6c0f03cff1223833163371d70e187e16dd460fb7ff7e0735e1be001b077c7bb50512ef07aedbd16b401ae811c1bfdab39093fd29682bd9898ffd2d8e6e553337fecd4fc2221ec84dc2690b042520cc57356b74724d79125abd9ce4bc3dcf24f85bc3720b1f2f7b7eae50564224b8abb58cdd90443757dabc1af9ba5dd652b543f3375363be291877e849b9ccbf67c8f7e86124c9c9555f63cdbc00c9fccd03ee84a04bb36cf0d620494936cc9bab33a057b74e289f8cbaee69dc7045b666acad0940972268c40dea0fcc9f5a407072ab49d3b242f40ec62c1032e5896e35619f038c1c2769711a9cc254a70bcf5b7e3b1a87ffecab0074e6ff570229ff7cbbc56ddbb218995e020911df504ef8944ac5e8e3240146d5d994927d04127a996e682fb850824400232eafcd445c9b47b4fa4485da0a2eba05117a703602bb8c7d4c1cea360a6cd44fe9b4eda932c553f18c2a77d02441bf5ef44eae18ee5fa6dcf88a192976f7bb0c274956045a91a5c5781ed629e8bbc5b0e3e51d72df6640389d49f4063e5550b4a81dba7be2cbeb582c7da70a8e1dc2338b716f86a9213f434d7e3cb4aad91d644d79c879507b94dd3ad484b63a9b22c2b2

###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# Revision: 1.4
#
# @include misc_func.inc
# @include global_settings.inc
#
###
include("compat_shared.inc");

##
# Name of the table where logs are stored.
##
global_var __SPAD_LOG_TABLE_NAME;
__SPAD_LOG_TABLE_NAME  = "logstore";

##
# For thread safety (some plugins call branch/fork)
##
global_var __SPAD_LOG_SQLDB_MUTEX;
__SPAD_LOG_SQLDB_MUTEX = __SPAD_LOG_TABLE_NAME + "_" + get_host_ip();

##
# Table definition for spad log table
#
# id      : log message id (integer auto increments)
# name    : log file name (128 CHAR) used when attached as a file, should be unique
#           for a logging session e.g. "ssh_get_info.log" or "virus_scanner_debug.log"
#           defaults to SCRIPT_NAME.log. This column is indexed.
# time    : time stamp for message, will be pre-appended to message when log created
# message : log message (unrestricted TEXT)
##
global_var __SPAD_LOG_TBL_SQL;

##
# SQL to insert a new log message
##
global_var __SPAD_LOG_INS_SQL;

##
# SQL to get unique log names
##
global_var __SPAD_LOG_NAM_SQL;

##
# SQL to check if table is created
##
global_var __SPAD_LOG_CHK_SQL;

##
# SQL to get text / time data for single log
##
global_var __SPAD_LOG_TXT_SQL;

__SPAD_LOG_INS_SQL = "INSERT INTO "+__SPAD_LOG_TABLE_NAME+" (name,message) VALUES(?,?)";
__SPAD_LOG_NAM_SQL = "SELECT DISTINCT name FROM "+__SPAD_LOG_TABLE_NAME;
__SPAD_LOG_CHK_SQL = "SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table' AND name='" +__SPAD_LOG_TABLE_NAME+"'";
__SPAD_LOG_TXT_SQL = "SELECT time,message FROM "+__SPAD_LOG_TABLE_NAME+" WHERE name=? ORDER BY time";
__SPAD_LOG_TBL_SQL =
  "CREATE TABLE IF NOT EXISTS "+__SPAD_LOG_TABLE_NAME+" (" +
    "id      INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
    "name    CHAR(128) NOT NULL ," +
    "time    DATETIME DEFAULT current_timestamp, " +
    "message TEXT" +
  "); " +
  "CREATE INDEX IF NOT EXISTS logstore_name_idx ON "+__SPAD_LOG_TABLE_NAME+"(name)";

##
# Adds log message specified by param 'message' to the
# log handle / file specified by param 'name'.
#
# @param message string required - message to log
# @param name    string optional - name of the log handle to log message
#                                  defaults to <SCRIPT_NAME>.log
#
# @remark Returns immediately if kb item 'global_settings/enable_plugin_debugging'
#         is not set.
#
# @remark If you are running in "CLI Mode" messages will be displayed directly
#         to the STDOUT and name will be ignored entirely.
#
# @remark It's highly recommended if you're logging in a plugin that branches / 
#         forks to not use the default name or to pre-append a thread specific
#         identifier to message, e.g.:
#
#            port = branch(list_of_ports)
#            spad_log(message:"("+port+") Opening connection ...");
#
#         Remember that functions like get_kb_item and get_single_install can
#         branch depending on the structure of the KB, its up to you to decide
#         if thread specific logging is appropriate for your logging needs in
#         these situations.
##
function spad_log(message,name)
{
  # Skip if plugin logging not enabled
  if(!get_kb_item("global_settings/enable_plugin_debugging"))
    return NULL;

  # Set default values
  if(isnull(name))
    name = ((SCRIPT_NAME - ".nasl") - ".nbin") + ".log";
  # Catch dev mistakes
  if(typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return NULL;
  }
  if(isnull(message) || typeof(message) !~ '(data|string)')
  {
    err_print("Parameter 'message' is null or an invalid type.");
    return NULL;
  }

  # If we're not running in CLI mode log to spad db
  if(!isnull(get_preference("plugins_folder")))
  {
    _spad_log_to_db(message:message,name:name);
  }
  # If we are in CLI mode show message directly
  else
  {
    display(message);
    if(message !~ '\n$')
      display('\n');
  }

  return NULL;
}

##
# combine spad_log with a call to exit 
# to report exit messages to spad log when needed
# 
# @param message, see spad_log message parameter, optional see remark
# @param name, see spad_log name parameter
# @param exit_level, see exit call for details, default to 0
# @param exit_msg, see exit call for details REQUIRED
#
# @remark if message is not supplied spad_log will use exit_msg
##
function spad_log_and_exit(message, name, exit_level, exit_msg)
{
  if (isnull(exit_msg))
    exit(0, "NO AUDIT TRAIL MESSAGE SUPPLIED!");

  if (isnull(exit_level))
    exit_level = 0;

  if (isnull(message))
  {
    spad_log(message:exit_msg, name:name);
    exit(exit_level, exit_msg);
  }
  else
  {
    spad_log(message:message, name:name);
    exit(exit_level, exit_msg);
  }
}

##
# Returns a structure that can be attached with security_report_with_attachments
##
function spad_log_get_report_attachments()
{
  local_var names,row,msgs,logs,txt,lidx;

  if(!_spad_log_has_inited())
    return NULL;

  names = query_scratchpad(__SPAD_LOG_NAM_SQL);

  if(empty_or_null(names))
    return NULL;

  logs = make_list();
  lidx = 0;
  foreach row (names)
  {
    if(isnull(row['name']))
      continue;

    txt = _spad_log_get_txt(name:row['name']);

    if(isnull(txt))
      continue;

    logs[lidx] = make_array();
    logs[lidx]["type" ] = "text";
    logs[lidx]["name" ] = row['name'];
    logs[lidx]["value"] = txt;
    lidx += 1;
  }
  return logs;
}


##
# Retrieve debug log for single plugin by name as a report attachment.
# 
# @param string optional - name of the log handle to log message
#                                  defaults to <SCRIPT_NAME>.log
#
# @return debug log as report attachment or NULL if no log found.
##
function spad_log_get_script_report_attachment(name)
{
  if(!_spad_log_has_inited())
    return NULL;

  if(isnull(name))
    name = ((SCRIPT_NAME - '.nasl') - '.nbin') + '.log';

  var log_text = _spad_log_get_txt(name:name);

  if (!isnull(log_text))
    return [{'type': 'text', 'name': name, 'value': log_text}];
  else
    return NULL;
}

##
# Adds log message specified by param 'message' to the
# log handle / file specified by param 'name'. Does
# the scratch pad database interaction only.
#
# @param message string required - message that to log
# @param name    string required - name of the log handle to log message
#
##
function _spad_log_to_db(message,name)
{
  if(typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return;
  }
  if(isnull(message) || typeof(message) !~ '(data|string)')
  {
    err_print("Parameter 'message' is null or an invalid type.");
    return;
  }

  if(!_spad_log_has_inited())
    _spad_log_init();

  query_scratchpad(__SPAD_LOG_INS_SQL,name,message);
}

##
# Get the log text for particular log
#
# @param name string required - name of the log to get the text of
#
# @remark a new line if always added to the end of messages if one
#         is not already present
##
function _spad_log_get_txt(name)
{
  local_var ret,row,txt;

  if(isnull(name) || typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return NULL;
  }
  
  ret = query_scratchpad(__SPAD_LOG_TXT_SQL, name);

  if(empty_or_null(ret))
    return NULL;
  txt = NULL;
  foreach row (ret)
  {
    txt += "["+row['time']+"] "+row["message"];
    if(row["message"] !~ '\n$') txt += '\n';
  }
  return txt;
}

##
# Creates the necessary SQLite tables for logging
##
function _spad_log_init()
{
  query_scratchpad(__SPAD_LOG_TBL_SQL);
}

##
# Checks to see the log structures have been initialized
##
function _spad_log_has_inited()
{
  local_var ret;

  ret = query_scratchpad(__SPAD_LOG_CHK_SQL);

  if(isnull(ret) || ret[0]["cnt"] == 0)
    return FALSE;
  return TRUE;
}
