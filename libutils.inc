#TRUSTED ad29259455f2323e98308f72595fcc859a5e92cb354ca769238e8612466055d71a8b6397170e9d83c061d0c9d58668b2ca3d0de29847cfa0d5c9892ef8c5c20e47f15d52d9d723497c29ca6781c7b554e852a483f805e96e053191840b4889d91004889628071cfa40a7bcb9f1a8289933e78f7164dfaf532969f62986d5e24f006c6b1d5dbd0d646c85ebc5794962ba72c9ccd35726fa624b495b1a530441fb46cfbcf776a6291c342e496dbe4ca1b4a9515beb0ca93785bc57c2d0a709b2c324aa0dc15b4e079a342c6a9e25fcc02c558289aaa768b757db186bce7284259e5a323f75311e7c5199e01c42f8d31b8dbfaff87dd885482faa15f22da0ba4210088fc96edb79b7d6f76f2be19de8edf852762bc1afde1c2a7fc1bd6c1c72a67e49db6658ca3ebcf3a8cd3d6b83c90a51fb66e67d474fc77e1b1dc17defec338b9ff8138d1e317fa0a5b4eb924c660a67012c91a955773d355e9b356ada2d248edd48c0f392c3745b2440761635c083b1679410f1d17795e9b6fe8df6172c7b5c21953492bb20e4967d46764a6c81760e1f96b95142421dab3c16bc85bce3ba69cdfb5ab9d2be85ab23ef52b8526c124b8c27aecb37b6a242bd9cbf585eb7e1963016bb7620349891bf0ac8cbb7aecf640efa314f605338b38ac59d6331257097efa134765e33d94d51727018d79d6874191e04818747f1584ac52a5690ff6726
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

include('libutils_errors_and_logging.inc');
include('validate.inc');

namespace libutils {
  ##
  # Default logger to be returned by get_default_logger()
  # Not initialized unless get_default_logger() is called
  ##
  global_var DEFAULT_LOGGER;

  ##
  # Gets default logger, initializing if needed
  # @return libutils::logger object
  ##
  function get_default_logger()
  {
    if (isnull(DEFAULT_LOGGER)) DEFAULT_LOGGER = new('libutils::logger');
    return DEFAULT_LOGGER;
  }

  ##
  # Wrapper for DEFAULT_LOGGER.dbg
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
  function dbg(src, msg, ddata)
  {
    var logger = get_default_logger();
    if (isnull(src)) src = FUNCTION_NAME;
    return logger.dbg(src:src, mdg:msg, ddata:ddata, FCT_ARGS(_FCT_ANON_ARGS));
  }

  ##
  # Wrapper for DEFAULT_LOGGER.set_err
  # Adds error to cumulative errors, logs error as debug message
  #
  # @anonparam [string]   Error message to append
  # @param [src:string]   Source to include with the message (optional)
  # @param [extra:string] Error details to append (optional)
  #
  # @return NULL
  ##
  function set_err(src, extra)
  {
    var logger = get_default_logger();
    if (isnull(src)) src = FUNCTION_NAME;
    return logger.set_err(src:src, extra:extra, FCT_ARGS(_FCT_ANON_ARGS));
  }

  ##
  # Wrapper for DEFAULT_LOGGER.ret_err
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
  function ret_err(src, ret, extra)
  {
    var logger = get_default_logger();
    if (isnull(src)) src = FUNCTION_NAME;
    return logger.ret_err(src:src, ret:ret, extra:extra, FCT_ARGS(_FCT_ANON_ARGS));
  }

  ##
  # Wrapper for DEFAULT_LOGGER.clear_err
  # Clears cumulative errors
  #
  # @return NULL
  ##
  function clear_err()
  {
    var logger = get_default_logger();
    return logger.clear_err();
  }

  ##
  # Wrapper for DEFAULT_LOGGER.get_last_err
  # Returns last error
  #
  # @return string  Last error message
  ##
  function get_last_err()
  {
    var logger = get_default_logger();
    return logger.get_last_err();
  }

  ##
  # Creates an object of the passed type and returns validate::obj()
  # with the new object passed to it for validation
  #
  # @anonparam [objname:string] Name of object to create
  #                             Example: "patch::tablemaker"
  #
  # @return [list] ret[0] bool      TRUE if object is valid, FALSE for error
  #                ret[1] bool/obj  Object if valid, FALSE for error
  #                ret[2] string    Error message if applicable
  ##
  function get_obj()
  {
    var logger = get_default_logger();
    var objname = _FCT_ANON_ARGS[0];
    var ret = validate::str_arg(arg:_FCT_ANON_ARGS[0]);
    if (!ret[0]) return logger.ret_err(src:FUNCTION_NAME, ret[2]);
    var obj = new(objname);
    if (isnull(obj)) return logger.ret_err(src:FUNCTION_NAME,
      'Failed to create object of type "' + _FCT_ANON_ARGS[0] + '".');
    return validate::obj(arg:obj, objname:objname);
  }
}
