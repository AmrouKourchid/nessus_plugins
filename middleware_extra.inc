#------------------------------------------------------------------------------
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# middleware_extra.inc
#
# Revision: 1.3
#
###

include("debug.inc");

#pragma const
global_var MIDDLEWARE_CONFIG_DIRS_KEY = "Config catalogs";
global_var MIDDLEWARE_CONFIG_FILES_KEY = "Config files";
global_var MIDDLEWARE_BINARY_DIR_KEY = "Binary catalog";
global_var MIDDLEWARE_BINARY_FILE_KEY = "Binary file";
global_var MIDDLEWARE_INSTALL_PATH_KEY = "Install path";
#pragma const(false)

##
#
# Object middleware_extra
#   Simple data structure encapsulating extra_no_report attributes that are common to all supported Linux middleware.
#   The resulting array contains data for audit plugins with enforced common key names, it should not be reported to the end users.
##
object middleware_extra
{
  var extra_array;

  ##
  # Constructs a ready to fill encapsulated middleware extra array, optionally setting binary catalog, binary file and installation paths.
  #
  # @anonparam [binary_dir:string] Path to the catalog containing middleware binaries.
  # @anonparam [binary_file:string] Path to the main middleware binary.
  # @anonparam [install_path:string] Path to the main installation catalog.
  ##
  function middleware_extra()
  {
    this.extra_array = {};
    this.extra_array[MIDDLEWARE_CONFIG_DIRS_KEY] = [];
    this.extra_array[MIDDLEWARE_CONFIG_FILES_KEY] = [];
    this.extra_array[MIDDLEWARE_BINARY_DIR_KEY] = '';
    this.extra_array[MIDDLEWARE_BINARY_FILE_KEY] = '';
    this.extra_array[MIDDLEWARE_INSTALL_PATH_KEY] = '';

    if(!isnull(_FCT_ANON_ARGS[0])) this.extra_array[MIDDLEWARE_BINARY_DIR_KEY] = _FCT_ANON_ARGS[0];
    if(!isnull(_FCT_ANON_ARGS[1])) this.extra_array[MIDDLEWARE_BINARY_FILE_KEY] = _FCT_ANON_ARGS[1];
    if(!isnull(_FCT_ANON_ARGS[2])) this.extra_array[MIDDLEWARE_INSTALL_PATH_KEY] = rstrip_slashes(str:_FCT_ANON_ARGS[2]);
  }

  ##
  # Strips any number of trailing slashes from the string.
  # @param [str:string] String to strip the slashes from.
  # @return [string] Cleaned string.
  ##
  function rstrip_slashes(str)
  {
    while(str[strlen(str) - 1] == '/') str = substr(str, 0, strlen(str) - 2);
    return str;
  }

  ##
  # Sets the path to the binary catalog.
  #
  # @param [dir:string] Path to the catalog containing middleware binaries.
  # @return NULL - this is just a setter.
  ##
  public function set_binary_dir(dir)
  {
    this.extra_array[MIDDLEWARE_BINARY_DIR_KEY] = dir;
    return NULL;
  }

  ##
  # Sets the path to the main binary.
  #
  # @param [file:string] Path to the main middleware binary.
  # @return NULL - this is just a setter.
  ##
  public function set_binary_file(file)
  {
    this.extra_array[MIDDLEWARE_BINARY_FILE_KEY] = file;
    return NULL;
  }

  ##
  # Sets the path to the installation catalog.
  #
  # @param [path:string] Path to the middleware installation path.
  # @return NULL - this is just a setter.
  ##
  public function set_install_path(path)
  {
    this.extra_array[MIDDLEWARE_INSTALL_PATH_KEY] = rstrip_slashes(str:path);
    return NULL;
  }

  ##
  # Adds information about a configured middleware instance: config directory and main config file paths.
  #
  # @param [config_dir:string] Path to the config catalog of this middleware instance.
  # @param [config_file:string] Path to the main config file of this middleware instance.
  #
  # @remark Both parameters should always be present, but if for any reason one of them is missing,
  #         an empty string will be inserted as its value. If both are missing, the function will do nothing.
  #
  # @return NULL - this is just an insert function.
  ##
  public function add_instance(config_dir, config_file)
  {
    if(isnull(config_dir) && isnull(config_file))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Both arguments missing, exiting!");
      return NULL;
    }
    if(isnull(config_dir))
    {
      dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "Missing config_dir, supplying empty string instead!");
      config_dir = '';
    }
    if(isnull(config_file))
    {
      dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "Missing config_file, supplying empty string instead!");
      config_file = '';
    }
    append_element(var:this.extra_array[MIDDLEWARE_CONFIG_DIRS_KEY], value:config_dir);
    append_element(var:this.extra_array[MIDDLEWARE_CONFIG_FILES_KEY], value:config_file);

    return NULL;
  }

  ##
  # Adds any other extra info. Existing values will be overwritten by new ones if any keys were already in the object's extra array.
  #
  # @remark Any values stored under middleware-specific keys will be ignored.
  #
  # @param [extra:array] A string:value array that will be merged with object's array. Can be passed anonymously.
  #
  # @return NULL - this is just an insert function.
  ##
  public function add_extra(extra)
  {
    if(isnull(extra))
      extra = _FCT_ANON_ARGS[0];
    for(var key in extra)
    {
      if(key == MIDDLEWARE_BINARY_DIR_KEY || key == MIDDLEWARE_BINARY_FILE_KEY ||
         key == MIDDLEWARE_CONFIG_DIRS_KEY || key == MIDDLEWARE_CONFIG_FILES_KEY ||
         key == MIDDLEWARE_INSTALL_PATH_KEY) continue;
      this.extra_array[key] = extra[key];
    }

    return NULL;
  }

  ##
  # Returns a ready to use extra_no_report array containing inserted data with enforced common key names.
  #
  # @remark Key names are defined as global variables at the beginning of the file.
  #
  # @return [array] An array with the following structure (key names may differ): {config_dirs:[string], config_files:[string], binary_dir:string, binary_file:string}.
  ##
  public function to_array()
  {
    return this.extra_array;
  }
}
