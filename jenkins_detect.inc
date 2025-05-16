###
# (C) Tenable Network Security, Inc.
#
# jenkins_detect.inc
# Revision: 0.5
#
###

include('spad_log_func.inc');
include('debug.inc');
include('compat_shared.inc');
include('lists.inc');

##
# Creates scratchpad table for plugins
##
function create_plugins_table()
{
  query_scratchpad(
      "CREATE TABLE IF NOT EXISTS jenkins_plugins(
        'id' INTEGER PRIMARY KEY AUTOINCREMENT,
        'path' TEXT,
        'pluginPath' TEXT,
        'source' TEXT,
        'port' INTEGER,
        'shortName' TEXT,
        'longName' TEXT,
        'mappedName' TEXT,
        'enabled' TEXT,
        'active' TEXT,
        'version' TEXT,
        'pluginVersion' TEXT,
        'jenkinsVersion' TEXT,
        'hudsonVersion' TEXT,
        'bundled' TEXT,
        'hasUpdate' TEXT,
        'url' TEXT
    );"
  );
}


##
# Insert plugin data into the table.
#
# @param [plugin:array] - properties of jenkins plugin
# @param [source:string] string required - value is either "remote" or "local"
# @param [port:integer] Port integer (optional)
# @param [path:string] string required in local detection - jenkins local installation path
# @param [plugin_path:string] string required in local detection - jenkins plugin installation path
##
function insert_into_plugins_table(plugin, port, source, path, plugin_path)
{
  var query_insert, query_values, query, query_debug, mapped_name;

  if (isnull(plugin)) exit(1, "Missing required parameter 'plugin'.");

  if (isnull(source)) exit(1, "Missing required parameter 'source'.");

  if (!(source == "local" || source == "remote")) exit(1, "Accepted values for parameter 'source': 'remote' or 'local'.");

  if (source == "local" && (empty_or_null(path) || empty_or_null(plugin_path))) exit(1, "Missing required parameter 'path' or 'plugin_path' in local detection.");

  if (source == "local")
  {
    query_insert = "INSERT INTO jenkins_plugins " +
                     "('port', 'shortName', 'longName', 'mappedName', 'pluginVersion', 'jenkinsVersion', 'hudsonVersion', 'url', 'source', 'path', 'pluginPath') ";
    query_values = "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    query = query_insert + query_values;
    mapped_name = get_mapped_name(long_name:plugin['Long-Name']);

    query_debug =
      query_insert + "VALUES (" + port + ", '" +
      plugin["Short-Name"] + "', '" + plugin["Long-Name"] + "', '" + mapped_name + "', '" +
      plugin["Plugin-Version"] + "', '" + plugin["Jenkins-Version"] + "', '" + plugin["Hudson-Version"] + "', '"
      + plugin["Url"] + "', '" + source + "', '" + path + "', '" + plugin_path + "');";

    dbg::detailed_log(
      src: FUNCTION_NAME,
      lvl: 3,
      msg: "Running the scratchpad query, for local source",
      msg_details:{"Query": {"lvl":3, "value": query_debug}});

    query_scratchpad(
        query,
        port,
        plugin["Short-Name"], plugin["Long-Name"], mapped_name, plugin["Plugin-Version"],
        plugin["Jenkins-Version"], plugin["Hudson-Version"], plugin["Url"], source, path, plugin_path
        );
  }
  else if (source == "remote")
  {
    query_insert = "INSERT INTO jenkins_plugins " + 
                 "('port', 'shortName', 'longName', 'mappedName', 'enabled', 'active', 'version', 'bundled', 'hasUpdate', 'url', 'source') ";
    query_values = "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    query = query_insert + query_values;
    mapped_name = get_mapped_name(long_name:plugin.longName);

    query_debug =
      query_insert + "VALUES (" + port + ", '" +
      plugin.shortName + "', '" + plugin.longName + "', '" + mapped_name + "', '" +
      plugin.enabled + "', '" + plugin.active + "', '" + plugin.version + "', '" + plugin.bundled + "', '" +
      plugin.hasUpdate + "', '" + plugin.url + "', '" + source + "');";

    dbg::detailed_log(
      src: FUNCTION_NAME,
      lvl: 3,
      msg: "Running the scratchpad query, for remote source",
      msg_details:{"Query": {"lvl":3, "value": query_debug}});

    query_scratchpad(
      query,
        port,
        plugin.shortName, plugin.longName, mapped_name, plugin.enabled, plugin.active,
        plugin.version, plugin.bundled, plugin.hasUpdate, plugin.url, source
    );
  }
}

##
# Retrieve the expected name to appear on an advisory
#
# @param [long_name:string] Detected name of plugin
#
# @return [string] plugin name as expected on an advisory
##
function get_mapped_name(long_name)
{
  var mapped_name = long_name;

  # Remove "jenkins" or "hudson" prefix
  mapped_name = ereg_replace(icase:TRUE, string:mapped_name, pattern:"^(bmc|jenkins|hudson)\s+", replace:'');

  # Add "plugin" if not there. And convert "plug-in" to "plugin"
  mapped_name = ereg_replace(icase:TRUE, string:mapped_name, pattern:"\s*(jenkins )?(plugin|plug-in)?$", replace:' plugin');

  return mapped_name;
}
