#TRUSTED 4d5a907ff7e2e5414fa0e0ebe348188705646950aefb9bc41dc9fc657c28e59660fecc6f6742de81568067b7cbd2639db72f9ea4782b1001072c34cfb04b9b98d8407f98a09a902b74fda3ca9acb181773a3f798eff16814b88d0196742dbeb79c359fca3b586e0162614932eb7f22d551b6042ec0fc6422bdef90769d43e1f001f61dfe8969c6892a9bbeecb34a5acfaa81e4030b8b17d6759415d7229074f1c3aa301619a7ac7854ad84dc62559b6d01f2014148d34c60afe678ea9cd7c6f8055ae44643a74bbd6f76ed04ada3847548f726c61a826f2c948fd7db4a9103f6b51a1e8c7a2a842ecb339c553e2482564df9b29173913e92094b4e49caa38c602cc93177cebe8bc0eda1d7700dabc8eba96707b3be89c8c7a11906b6bcf55f74cc2334807bd83bab9df1767d8b00e676351f1d3c02c149a0af43b2e8c257ea0b46341f9cff9d29c0fbeda620f49dd9c55bc18a22bc5a812bf1fe54906914defa283699822e10e75c81557c87d7d822ce6c36c83a34e9ba5edb4789033bce952e943f8ff0fac436f0c8c02dc95737b1df47cc9a0716f8876fbc2c7e63d350b60d8eca0dfcc6c55b6ecbcf21623844e67add8c7d1e8144de67f9913f01ad0c77798de67f7287e7dff1c47872566c272cdf5b2f35fedbf820ba16417f07ec6e2ee4b93c12856c280a96c9ac9b07511ab1facdbf04b0f9d3d809ebeaffbd3c5a0591
#TRUST-RSA-SHA256 72603bcf3b57aa6dde7b2e51b430e3fd72906bbaf66376e9644e79493e79dd736cf09e4692f999f9d1ef3938a31cb6e34ef2965c914b69852e86a0d947bb27f5a287aa0e6fad507288595b27e78f10d6af62dedce908433627796b10d13235ff33b93fffb13aff7f3d3ccf9da81572fd03bf86d624d1b6d22a914bc819d486c5b01b7d032020f42a866b1278fc7ad59b6cffebb552a9b7ac321a385533e18726651214c890499329caf30d7f64c6edff68e8405c9f135c29fd54dfdf1fdbc19f76fbde81712cc5a4cba744aa145a5b24a873b98037d1eb5f667c001d6ecb30d6f48d5e5254d94eaf96d38dd399e1ae6e2af4bd02c86c563ae25aab587a71701b9b4a42731c1f4846a9be1b4fa899ca894052db553af6acea5a4dbf3481d176d28757a98758a170bc2d19be99c9be0b133113f2d0462c787701989d6dadf6756ee2f29f3a2da47393d56fac3706a1c1d99c47d16e2bbba70ce8b8df46baf50a09963029b806afff926894758fe6ada7dcd168aaa38c06b1b971838b15db943f0c83cb5f2f344cad4600a4e0b37279328d55b3f3108a4c0c42f3963b495306891501c11427f861fd86b160a4031dc187949a5352c54b9e06911b46bd97472031191280db15060ac6ca1cbd5aea08c9322c08153f1722e668fed6bdad9733f6c0190aaee48be45000e588704a1064f377d544d3ca50ba20b034e0da3a60947e732c
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# Revision: 0.4
#
# <at:var at:name="NOGPL" />
###

include('debug.inc');
include('libutils.inc');
include('compat_shared.inc');

##
# The validate namespace provides functions to validate arguments,
# return the validation result, and generate an error message if
# validation fails. It also holds a reference to a logger used for
# errors and debugging. The logger can be overridden by setting
# validate::logger to a different logger instance.
# For library-specific validation functions, the validate namespace
# can be "extended" by creating a validate namespace within the
# library. For example, from within the 'patch' namespace, calls to
# validate:: functions and patch::validate:: functions can both be
# made using the syntax validate::func(). This can also be used to
# override the validate:: functions below; if a function 'func()'
# exists in both namespaces, a call to validate::func() from within
# the patch namespace would call patch::validate::func()
##
namespace validate {
  ##
  # Logger object to use for errors and logging
  ##
  var logger = libutils::get_default_logger();

  # Basic data type checker
  var checker = {
    data : new validate::type_checker()
  };

  ##
  # Validates that an argument is not empty or NULL and is a valid type
  # If both 'types' and 'ex_types' are passed, the arg type only needs
  # to match a type in one or the other
  #
  # @param [arg:string]     Argument value to validate
  # @param [argname:string] Name of argument being validated to be
  #                         included in error message (optional)
  # @param [types:list]     List of valid variable types (typeof())
  # @param [ex_types:list]  List of valid variable types (typeof_ex())
  # @param [constraints:array] Expects at least one of the following keys:
  #          [types:list]     List of valid variable types (typeof())
  #          [ex_types:list]  List of valid variable types (typeof_ex())
  #
  # @return [list] ret[0] bool   TRUE if arg is valid, FALSE for error
  #                ret[1] bool   FALSE if error, unused if successful
  #                ret[2] string Error message if applicable
  ##
  function arg_type(arg, argname, types, ex_types, constraints)
  {
    if (!constraints.types) constraints.types = types;
    if (!constraints.ex_types) constraints.ex_types = ex_types;

    # Function usage, unrelated to the arg itself
    if (isnull(constraints.types) && isnull(constraints.ex_types))
      return logger.ret_err(src:FUNCTION_NAME,
        'Neither "types" nor "ex_types" was passed, at least one is required');

    if (!isnull(constraints.types) && typeof_ex(constraints.types) != 'list')
      return logger.ret_err(src:FUNCTION_NAME,
        'Bad type for "types", expected list, got ' + typeof_ex(constraints.types) +
        ': ' + serialize(constraints.types));
    if (!isnull(constraints.ex_types) && typeof_ex(constraints.ex_types) != 'list')
      return logger.ret_err(src:FUNCTION_NAME,
        'Bad type for "ex_types", expected list, got ' + typeof_ex(constraints.ex_types) +
        ': ' + serialize(constraints.ex_types));

    var res = _check_type(arg:arg, argname:argname, constraints:constraints);
    if (res[0]) return res;
    return logger.ret_err(src:FUNCTION_NAME, res[2]);
  }

  ##
  # Low-level function to check type, does not log errors
  #
  # @param [arg:string]     Argument value to validate
  # @param [argname:string] Name of argument being validated to be
  #                         included in error message (optional)
  # @param [constraints:array] Expects at least one of the following keys:
  #          [types:list]     List of valid variable types (typeof())
  #          [ex_types:list]  List of valid variable types (typeof_ex())
  #
  # @return [list] ret[0] bool   TRUE if arg is valid, FALSE for error
  #                ret[1] bool   FALSE if error, unused if successful
  #                ret[2] string Error message if applicable
  ##
  function _check_type(arg, argname, constraints)
  {
    if (argname) argname = '"'+argname+'" ';
    if (isnull(arg))
      return [FALSE, FALSE, 'Argument ' + argname + 'is NULL.'];

    if (constraints.types)
      foreach var type (constraints.types)
        if (typeof(arg) == type) return [TRUE];

    if (constraints.ex_types)
      foreach var ex_type (constraints.ex_types)
        if (typeof_ex(arg) == ex_type) return [TRUE];

    var errmsg =
      'Unexpected variable type "' + typeof(arg) + '" for argument ' +
      argname + ': ' + serialize(arg);
    if (!isnull(constraints.types))
      errmsg += '\nAcceptable types    : ' + serialize(constraints.types);
    if (!isnull(constraints.ex_types))
      errmsg += '\nAcceptable ex_types : ' + serialize(constraints.ex_types);

    return [FALSE, FALSE, errmsg];
  }

  ##
  # Validates that an argument is not empty or NULL and is a valid
  # string type. Both "string" and "data" are accepted to allow both
  # pure and impure strings. If "int_ok:TRUE" is passed, then type
  # "int" is also allowed.
  #
  # @param [arg:string]     Argument value to validate
  # @param [argname:string] Name of argument being validated to be
  #                         included in error message (optional)
  # @param [empty_ok:bool]  TRUE if empty string is allowed, defaults
  #                         to FALSE (optional)
  # @param [int_ok:bool]    TRUE if int is also an acceptable data
  #                         type, defaults to FALSE (optional)
  # @param [pos:bool]       TRUE if integer should be > 0
  # @param [constraints:array] Accepts the following keys:
  #          [empty_ok:bool]  TRUE if empty string is allowed, defaults
  #                           to FALSE (optional)
  #          [int_ok:bool]    TRUE if int is also an acceptable data
  #                           type, defaults to FALSE (optional)
  #          [pos:bool]       TRUE if integer should be > 0
  #          [min:int]        Minimum acceptable value, if integer
  #
  # @return [list] ret[0] bool   TRUE if arg is valid, FALSE for error
  #                ret[1] bool   FALSE if error, unused if successful
  #                ret[2] string Error message if applicable
  ##
  function str_arg(arg, argname, empty_ok, int_ok, pos, constraints)
  {
    if (isnull(constraints.empty_ok)) constraints.empty_ok = empty_ok;
    if (isnull(constraints.int_ok))   constraints.int_ok   = int_ok;
    if (isnull(constraints.pos))      constraints.pos      = pos;

    var ret = _check_type(arg:arg, argname:argname, constraints:{types:['string', 'data']});
    if (ret[0])
    {
      if (!empty(arg) || constraints.empty_ok) return ret;
      return logger.ret_err(src:FUNCTION_NAME, 'Argument "' + argname + '" is empty.');
    }
    if (!constraints.int_ok) return ret;
    return int_arg(arg:arg, argname:argname, constraints:constraints);
  }

  ##
  # Validates that an argument is not empty or NULL and is "int" type
  #
  # @param [arg:int]        Argument value to validate
  # @param [argname:string] Name of argument being validated to be
  #                         included in error message (optional)
  # @param [pos:bool]       TRUE if integer should be > 0
  # @param [constraints:array] Accepts the following keys:
  #          [pos:bool]       TRUE if integer should be > 0 (optional)
  #          [min:int]        Minimum acceptable value of integer
  #
  # @return [list] ret[0] bool   TRUE if arg is valid, FALSE for error
  #                ret[1] bool   FALSE if error, unused if successful
  #                ret[2] string Error message if applicable
  ##
  function int_arg(arg, argname, pos, constraints)
  {
    if (isnull(constraints.pos)) constraints.pos = pos;
    if (constraints.pos && (isnull(constraints.min) || constraints.min < 1))
      constraints.min = 1;

    var ret = arg_type(arg:arg, argname:argname, constraints:{types:['int']});
    if (!ret[0] || isnull(constraints.min)) return ret;

    if (arg < constraints.min)
    {
      if (argname) argname = '"' + argname + '" ';
      return logger.ret_err(src:FUNCTION_NAME, 'Argument ' + argname + 
        'is < ' + constraints.min + ' : ' + arg);
    }
    return [TRUE];
  }

  ##
  # Validates that an argument is a valid boolean value. Acceptable
  # values includes explicit boolean type (native globals true and false)
  # and int 0 or 1 (native globals TRUE and FALSE).
  #
  # @param [arg:int]        Argument value to validate
  # @param [argname:string] Name of argument being validated to be
  #                         included in error message (optional)
  # @param [constraints:array] Unused, param exists for compatibility
  #
  # @return [list] ret[0] bool   TRUE if arg is valid, FALSE for error
  #                ret[1] bool   FALSE if error, unused if successful
  #                ret[2] string Error message if applicable
  ##
  function bool_arg(arg, argname, constraints)
  {
    # Type check needs to be done because values such as non-empty
    # strings are truthy
    var ret = arg_type(arg:arg, argname:argname, constraints:{types:['int', 'boolean']});
    if (!ret[0]) return ret;

    # true == TRUE and false == FALSE
    if (arg != TRUE && arg != FALSE)
    {
      if (argname) argname = '"' + argname + '" ';
      return logger.ret_err(src:FUNCTION_NAME, 'Argument ' + argname + 'is not boolean : ' + arg);
    }
    return [TRUE];
  }

  ##
  # Validates that an argument is a valid plugin name
  #
  # @param [arg:int]        Argument value to validate
  # @param [argname:string] Name of argument being validated to be
  #                         included in error message (optional)
  # @param [constraints:array] Unused, param exists for compatibility
  #
  # @return [list] ret[0] bool   TRUE if arg is valid, FALSE for error
  #                ret[1] bool   FALSE if error, unused if successful
  #                ret[2] string Error message if applicable
  ##
  function script_fname_arg(arg, argname, constraints)
  {
    var ret = str_arg(arg:arg, argname:argname);
    if (!ret[0]) return ret;
    if (arg !~ '^[a-zA-Z0-9\\.+{}_-]+\\.(nasl|nbin)$')
    {
      if (argname) argname = '"' + argname + '" ';
      return logger.ret_err('Argument ' + argname +
        'is not a valid script_fname (plugin filename): ' + arg);
    }
    return [TRUE];
  }

  ##
  # Validates that an object argument is the correct type
  #
  # @param [arg:object]     Object to validate
  # @param [argname:string] Name of argument being validated to be
  #                         included in error message (optional)
  # @param [objname:string] Name of object being validated (optional)
  # @param [constraints:array] Accepts the following keys:
  #          [objname:string] Name of object being validated (optional)
  #
  # @return [list] ret[0] bool      TRUE if object is valid, FALSE for error
  #                ret[1] bool/obj  Object if valid, FALSE for error
  #                ret[2] string    Error message if applicable
  ##
  function obj(arg, argname, objname, constraints)
  {
    if (isnull(constraints.objname)) constraints.objname = objname;
    var ret;
    if (!isnull(constraints.objname))
      ret = arg_type(arg:arg, argname:argname, constraints:{ex_types:[constraints.objname]});
    else
      ret = arg_type(arg:arg, argname:argname, constraints:{types:['object']});
    if (!ret[0]) return logger.ret_err(src:FUNCTION_NAME, ret[2]);
    return [TRUE, arg];
  }

  ##
  # Validates that the argument is a string and in specified allow list.
  #
  # @param [arg:str]           Argument value to validate
  # @param [argname:str]       Name of argument being validated to be included in error message
  # @param [constraints:array] Accepts the following keys:
  #          [list:list]        List of acceptable values
  #
  # @return [list] ret[0] bool      TRUE if argument is valid, FALSE for error
  #                ret[1] bool      FALSE for error
  #                ret[2] string    Error message if applicable
  ##
  function str_in_list(arg, argname, constraints)
  {
    var ret, errors;

    errors = [];

    # Check for string
    ret = validate::str_arg(arg:arg, argname:argname);
    if (!ret[0]) append_element(var:errors, value:ret[2]);

    # Check if argument is in specified list
    if (!empty_or_null(constraints.list) && !contains_element(var:constraints.list, value:arg))
    {
      ret = logger.ret_err(src:FUNCTION_NAME, strcat('Argument "', argname, '" is not valid : ', obj_rep(arg)));
      append_element(var:errors, value:ret[2]);
    }

    # Invalid argument
    if (!empty_or_null(errors))
      return [ FALSE, FALSE, join(errors, sep:'\n') ];

    # Valid argument
    return [ TRUE ];
  }

  ##
  # Validates multiple args using a passed list of checks, each of
  # which is an array defining the arg to check and the constraints
  #
  # @param [checks:list] List of check definition arrays, see usage for examples
  #   Check fields:
  #     arg           : Value to be checked
  #     argname       : Name of parameter arg was provided for, used in error messages (optional)
  #     checker       : validate::checker object containing func and constraints (required)
  #     optional      : TRUE if it's ok for arg to be NULL (default FALSE) (optional)
  #     optional_with : Value of another arg or var such that if the optional_with value is not NULL,
  #                     the arg value can be NULL (require one or the other) (optional)
  #
  # @param [check_all:bool] TRUE if all checks should be executed and
  #                         all errors should be reported, default
  #                         FALSE to return at first error
  #
  # @return [list] ret[0] bool   TRUE if all args are valid, FALSE for error
  #                ret[1] bool   FALSE if error, unused if successful
  #                ret[2] string Error message if applicable
  #
  # @remark This functionality may be overkill for a plugin, but can
  # be useful for a library. If there is a standard set of arguments
  # that is commonly used throughout the library, a wrapper function
  # can be created that accepts named args, assigns the appropriate
  # check definition to each arg, and then passes the checks to this
  # function. See usage for an example.
  #
  # Usage :
  #
  # # Example 1 - Inline usage
  # # Create checker objects to template check types
  # var int_pos = new('validate::checker', @validate::int_arg, {pos:TRUE});
  # var str_only = new('validate::checker', @validate::str_arg});
  # var str_int_ok = new('validate::checker', @validate::str_arg, {int_ok:TRUE});
  # var fname = new('validate::checker', @validate::script_fname_arg});
  # # Create list of validation checks to run
  # var checks = [
  #   {arg:host_id, argname:'host_id', checker:int_pos},
  #   {arg:prod_name, argname:'prodname', checker:str_only},
  #   {arg:version, argname:'version', checker:str_int_ok, optional:TRUE},
  #   {arg:location, argname:'location', checker:str_only, optional:TRUE},
  #   {arg:plugin_id, checker:int_pos, optional_with:script_fname},
  #   {arg:script_fname, checker:fname, optional_with:plugin_id}
  # ];
  # # Validate multiple args using checks
  # var ret = validate::multiple_args(checks:checks);
  # if (!ret[0]) return ret_err(src:FUNCTION_NAME, ret[2]);
  #
  # Example 2 - Wrapper function
  # namespace my_library {
  #   # Create checker objects to template check types
  #   chk_str_only     = new('validate::checker', @validate::str_arg});
  #   chk_str_int_ok   = new('validate::checker', @validate::str_arg, {int_ok:TRUE});
  #   # Create lookup array for checkers
  #   global_var chk = {};
  #   chk.prod_name    = chk_str_only;
  #   chk.prod_path    = chk_str_only;
  #   chk.prod_ver     = chk_str_int_ok;
  #   chk.prod_edition = chk_str_int_ok;
  #   chk.script_fname = new('validate::checker', @validate::script_fname_arg});
  #
  #   # Wrapper function to validate common library args
  #   function named_args(check_all, args, optional)
  #   {
  #     # Build list of checks
  #     local_var i, argname, checker, check, checks = [];
  #     foreach argname (keys(args))
  #     {
  #       checker = chk[argname];
  #       if (isnull(checker)) return logger.ret_err(src:FUNCTION_NAME,
  #         'No checker found for argname "' + argname + '", unable to validate.');
  #       check = {arg:args[argname], argname:argname, checker:checker};
  #       if (optional[argname]) check.optional = TRUE;
  #       append_element(var:checks, value:check);
  #     }
  #     # Pass through to multiple_args() and return results
  #     return validate::multiple_args(checks:checks, check_all:check_all);
  #   }
  #
  #   # Library function using wrapper function
  #   function save_product_install(prod_name, prod_path, prod_ver, prod_edition, script_fname)
  #   {
  #     # Validate args
  #     var ret = named_args(args:{prod_name:prod_name, prod_path:prod_path,
  #                                prod_ver:prod_ver, prod_edition:prod_edition,
  #                                script_fname:script_fname},
  #                          optional:{prod_edition:TRUE, script_fname:TRUE});
  #     if (!ret[0]) return ret_err(src:FUNCTION_NAME, ret[2]);
  #     ... continue with function execution ...
  #   }
  # }
  #
  ##
  function multiple_args(checks, check_all)
  {
    if (typeof_ex(checks) != 'list')
      return logger.ret_err(src:FUNCTION_NAME, 'Invalid "checks" var, expected list');

    var i, ret, check, tmp_err, errs = [];
    for (i=0; i<len(checks); i++)
    {
      check = checks[i];
      if (typeof_ex(check.checker) != 'validate::checker')
        ret = [FALSE, FALSE, 'Invalid checker, expected "validate::checker" object. Check : ' + serialize(check)];
      else ret = check.checker.validate(
                   arg           : check.arg,
                   argname       : check.argname,
                   optional      : check.optional,
                   optional_with : check.optional_with);

      if (!ret[0])
      {
        if (!check_all) return logger.ret_err(src:FUNCTION_NAME, 'Validation failed: ' + ret[2]);
        append_element(var:errs, value:ret[2]);
      }
    }
    if (len(errs) == 0) return [TRUE];
    return logger.ret_err(src:FUNCTION_NAME, extra:join(errs, sep:'\n'),
      'Validation failed for one or more argument checks.');
  }

  ##
  # Simple empty or null check with logging for argument checking in functions.
  #
  # @param [src:str]    FUNCTION_NAME global variable from the function call this function
  # @param [args:array] arguments to check with key and value using the same name (e.g. { path : path }
  #
  # @return true if all the arguments are not empty or null
  #         false if at least on argument is empty or null
  #         NULL if an error occurred
  ##
  function empty_or_null_args(src, args)
  {
    var valid = true;

    for (var required_arg in args)
    {
      if (empty_or_null(args[required_arg]))
      {
        dbg::detailed_log(lvl:1, src:src, msg:strcat('Missing required argument "', required_arg, '"'));
        valid = false;
      }
    }

    return valid;
  }

  ##
  # Checker object to template and execute validation checks for
  # validate::multiple_args()
  #
  # Usage:
  #
  # # Example 1
  # var int_pos = new('validate::checker', @validate::int_arg, {pos:TRUE});
  # var res = int_pos.validate(id);
  # if (!res[0]) return ret_err(src:FUNCTION_NAME, ret[2]);
  #
  # # Example 2
  # # Create checker objects to template check types
  # var int_pos = new('validate::checker', @validate::int_arg, {pos:TRUE});
  # var str_only = new('validate::checker', @validate::str_arg});
  # var str_int_ok = new('validate::checker', @validate::str_arg, {int_ok:TRUE});
  # var fname = new('validate::checker', @validate::script_fname});
  # # Create list of validation checks to run
  # var checks = [
  #   {arg:host_id, argname:'host_id', checker:int_pos},
  #   {arg:prod_name, argname:'prodname', checker:str_only},
  #   {arg:version, argname:'version', checker:str_int_ok, optional:TRUE},
  #   {arg:location, argname:'location', checker:str_only, optional:TRUE},
  #   {arg:plugin_id, checker:int_pos, optional_with:script_fname},
  #   {arg:script_fname, checker:fname, optional_with:plugin_id}
  # ];
  # # Validate multiple args using checks
  # var ret = validate::multiple_args(checks:checks);
  # if (!ret[0]) return ret_err(src:FUNCTION_NAME, ret[2]);
  ##
  object checker {
    # Validation function reference
    var func;
    # Constraints array for validation function
    var constraints;

    ##
    # Constructor
    #
    # @anonparam [func:function ref] Reference to function to validate arg
    # @anonparam [constraints:array] Array of constraints to pass to func (optional)
    ##
    function checker()
    {
      this.func = _FCT_ANON_ARGS[0];
      this.constraints = _FCT_ANON_ARGS[1];
    }

    ##
    # Runs check and returns result. Evaluates arg value based on
    # optional and optional_with. Passes arg, argname, and constraints
    # to validation function.
    #
    # @param [arg:any]           Argument value to validate
    # @anonparam [arg:any]       Argument can also be passed anonymously
    # @param [argname:string]    Name of argument being validated to be
    #                            included in error message (optional)
    # @param [optional:bool]     TRUE if it's ok for arg to be NULL (optional, default FALSE)
    # @param [optional_with:any] Value of another arg such that if that arg is not NULL,
    #                            this one can be NULL (require one or the other)
    #
    # @return [list] ret[0] bool   TRUE if arg is valid, FALSE for error
    #                ret[1] bool   FALSE if error, unused if successful
    #                ret[2] string Error message if applicable
    ##
    public function validate(arg, argname, optional, optional_with)
    {
      if (isnull(arg)) arg = _FCT_ANON_ARGS[0];
      # If arg is NULL, but is optional or its optional_with is not NULL,
      # return success
      if (isnull(arg) && (optional || !isnull(optional_with)))
        return [TRUE];

      if (typeof(this.func) != 'function')
      {
        return validate::logger.ret_err(src:'validate::checker::validate',
          '"func" is not a valid function reference: ' + typeof(this.func));
      }
      if (!isnull(this.constraints) && typeof_ex(this.constraints) != 'array')
      {
        return validate::logger.ret_err(src:'validate::checker::validate',
          '"constraints" is not an array: ' + typeof_ex(this.constraints));
      }
      return this.func(arg:arg, argname:argname, constraints:this.constraints);
    }
  }

  ##
  # Data type checker
  ##
  object type_checker {

    var str, int, bool, list, array;

    function type_checker()
    {
      str   = new validate::checker(@validate::str_arg);
      int   = new validate::checker(@validate::int_arg);
      bool  = new validate::checker(@validate::bool_arg);
      list  = new validate::checker(@validate::arg_type, {ex_types:['list']});
      array = new validate::checker(@validate::arg_type, {ex_types:['array']});
    }
  }
}
