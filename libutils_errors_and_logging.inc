#TRUSTED 995bc63e05ef98ced04a760c5d60e6b60edc79b52b6cd670746215530b2674e7a1fb704257bbffe9bae69b22cf16f5c8b9e6c8582d0743c89d0dff3c5a69a380b64f9d557fe5a4326436d9896fc3208865f459810a72efc9f29bef1603d84244fd3514693579216ac94388c6a069ef8b24bdb006fb948c7d6ca2b4111b741be608ae3c0b59634d63b9d66cae4122eb8354c3c92b0978ba51631df1bda7ac486530e73998f5607c08dbfcb9359d66b3f0d5624ad131c2e0d6b09b8f32666fda65b6dc24cf1307e08b53df67649b7b776a906eaa5cde278f2f6091cd31b9f0c7ee00b2327412621cb1e9b391395a1f01118d9c91129de2a14ac134038d9448cfdaa379e1322afdfc2db720c069682c07626ac25084f5cd2949bfbb1c195dcd87b0fff86759fe27011f722d0addad8c1919815c979c6ce8ce763ff2c303a10dedf94620a4c1fb58f43af1fca437d1607c8e98dd0fdead255bd5385af598f6439df88e36c3953dea66513a0780a9b2c50eb6a17c53863b4f127a8f27b23b7bd298b4027b2c03f99fd28a01b04701d6e2a6934f2408c635316cd0dc17db02f98da066f8964e44720b529139da340b3e4965f68c0787deb917fb38e17b0f65104d786c170d29fafa6d90a8b95d208ad8876ab756a92d3b2b5298588605fb6ca8098537b3addcafc7608fb38b6beede2a41eb85ca378cdd9c4598b7af1acfdbec8ddb2a
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# Revision: 0.1
#
# <at:var at:name="NOGPL" />
###

include('debug.inc');
include('compat_shared.inc');

# Workaround for namespace issues with SCRIPT_NAME
global_var THIS_SCRIPT = SCRIPT_NAME;

namespace libutils {
  ##
  # Logger object to provide advanced logging functionality, cumulative
  # error logging, and return value standardization. Create a new logger
  # object for each library in order to keep namespace, logname, and
  # cumulative errors separate for each library.
  ##
  object logger {
    ##
    # Object name for debugging
    ##
    var objname = 'libutils::logger::';

    ##
    # Namespace name to use for debugging
    ##
    var NS = NULL;

    ##
    # Filename to use for spad_log
    ##
    var LOGNAME = NULL;

    ##
    # Whether or not to prepend script name
    ##
    var use_scriptname = FALSE;

    ##
    # Cumulative errors
    ##
    var ERRS = [];

    ##
    # Constructor for logger, sets NS and LOGNAME
    # @anonparam [NS:string] Name of namespace (optional)
    # @anonparam [LOGNAME:string] Filename to use for spad_log
    # @return NULL
    ##
    function logger()
    {
      if (!isnull(_FCT_ANON_ARGS[0])) this.set_namespace(_FCT_ANON_ARGS[0]);
      if (!isnull(_FCT_ANON_ARGS[1])) this.set_logname(_FCT_ANON_ARGS[1]);
      return NULL;
    }

    ##
    # Sets NS (namespace name)
    # @anonparam [NS:string] Name of namespace (optional)
    # @return NULL
    ##
    public function set_namespace() { this.NS = _FCT_ANON_ARGS[0]; }

    ##
    # Sets LOGNAME
    # @anonparam [LOGNAME:string] Filename to use for spad_log (optional)
    # @return NULL
    ##
    public function set_logname() { this.LOGNAME = _FCT_ANON_ARGS[0]; }

    ##
    # Sets use_scriptname
    # @anonparam [bool] TRUE or FALSE
    # @return NULL
    ##
    public function use_scriptname() { this.use_scriptname = _FCT_ANON_ARGS[0]; }

    ##
    # Passthrough for debugging to ensure correct logname so that all
    # debugging from a library is directed to a single file for each
    # target. Format includes script name, namespace, and source function.
    #
    # @param [src:string] The source to include with the message (optional)
    # @param [msg:string] The message to log
    # @param [ddata:data] The data to dump to hex/ascii and append
    #
    # @return NULL
    ##
    public function dbg(src, msg, ddata)
    {
      if (isnull(src)) src = objname + FUNCTION_NAME;
      if (!isnull(this.NS) && this.NS >!< src) src = this.NS + src;
      if (this.use_scriptname) src = THIS_SCRIPT + ' ' + src;
      dbg::log(name:this.LOGNAME, src:src, msg:msg, ddata:ddata);
      return NULL;
    }

    ##
    # Adds error to cumulative errors, logs error as debug message
    #
    # @anonparam [string]   Error message to append
    # @param [src:string]   Source to include with the message (optional)
    # @param [extra:string] Error details to append (optional)
    #
    # @return NULL
    ##
    public function set_err(src, extra)
    {
      if (isnull(src)) src = objname + FUNCTION_NAME;
      var err = _FCT_ANON_ARGS[0];
      if (isnull(err)) err = 'Unknown error.';
      err = '[ERROR] ' + err;
      if (!isnull(extra)) err += '\n  Error details : ' + extra;
      this.dbg(src:src, msg:err);
      append_element(var:this.ERRS, value:src + '(): ' + err);
      return NULL;
    }

    ##
    # Passes error to set_err() and returns the error message in the
    # standard failure response format for the library (default) or
    # returns a custom "ret" value
    #
    # @anonparam [string]   Error message to append
    # @param [src:string]   Source to include with the message (optional)
    # @param [extra:string] Error details to append (optional)
    # @param [ret:string]   Value to return instead of default (optional)
    #
    # @return (default) [list] ret[0] bool    FALSE (calling function failed)
    #                          ret[1] bool    FALSE (no data to return)
    #                          ret[2] string  Error message
    # @return (optional) "ret" argument
    ##
    public function ret_err(src, ret, extra)
    {
      if (isnull(src)) src = objname + FUNCTION_NAME;
      var err = _FCT_ANON_ARGS[0];
      if (isnull(err)) err = 'Unknown error.';
      if (extra) err += '\n  Error details : ' + extra;
      this.set_err(src:src, err);
      if (!isnull(ret)) return ret;
      return [FALSE, FALSE, err];
    }

    ##
    # Clears cumulative errors
    #
    # @return NULL
    ##
    public function clear_err()
    {
      this.ERRS = [];
      return NULL;
    }

    ##
    # Returns last error
    #
    # @return string  Last error message
    ##
    public function get_last_err()
    {
      if (len(this.ERRS) == 0) return '';
      return chomp(this.ERRS[max_index(this.ERRS)-1]);
    }
  }
}
