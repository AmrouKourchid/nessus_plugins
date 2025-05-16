include('compat_shared.inc');
include('debug.inc');
include('install_func.inc');
include('sets.inc');
include('vcf.inc');
include('package_manager_utils.inc');

# vdf := vuln data/detection framework
namespace vdf {

  var VULN_CHECK_SPECS = {
    '1.0': @vuln_check_v1,
    '1.0p' : @package_vuln_check_v1
  };

  var VALID_INPUT_SPECS = {
    '1.0': @valid_input_v1,
    '1.0p': @valid_input_v1
  };

  var PROPERTY_TRANSLATORS = {
    'os': @get_os,
    'distro': @get_distro,
    'os_version': @get_os_version,
    'paranoia': @get_paranoia,
    'vendor_unpatched': @get_vendor_unpatched_scan_config
  };

  var CHECK_ALGORITHMS = {
    'default': @default_check
  };

  var VERSION_PARSERS = {
    'default': @default_parser
  };

  var REPORT_BUILDERS = {
    'default': @default_report,
    'unpatched': @unpatched_report
  };


  ##
  # Gathers the detection data based on the vuln_data object provided
  # and determines if vulnerable based on the constraints. 
  #
  # @param [vuln_data:array]    a "vuln_data" object, i.e. an array adhering to the vuln_data schema
  # @param [severity:int]       defines the severity of the vuln(s) in vuln_data, used for reporting
  # @param [flags:array]        xss/sqli/xsrf flags for the vuln(s) in vuln_data, used for reporting
  #
  # @return [vcf::Error|true]   returns a vcf::Error if one was thrown
  #                             returns true if no errors occur and report_result returns successfully
  ##
  function check_and_report(vuln_data, severity, flags)
  {
    var schema_validation = valid_input_by_spec(vuln_data:vuln_data);
    if (vcf::is_error(schema_validation))
      return schema_validation;

    # check_by_spec forks so multiple threads will return from it
    var check_result = check_by_spec(vuln_data:vuln_data);
    if (vcf::is_error(check_result))
      return check_result;
    if (!empty_or_null(check_result.error) && vcf::is_error(check_result.error))
      return check_result.error;
    
    # if check_result isn't a vcf:Error, then it's an array of results
    # the array can be empty if no vulns were found
    var report_type = get_report_type(vuln_data:vuln_data);
    return report_result(
      top_level_report_type:report_type,
      check_result:check_result,
      severity:severity,
      flags:flags
    );
  }

  ##
  # Handles errors thrown (if any) by vdf::check_and_report and exits the plugin
  # If an error was thrown, print it as part of the exit call.
  # Otherwise exit with a success message.
  #
  # @param [vdf_result:object|boolean]  expected to be either a vcf::Error to print, or true
  #
  ##
  function handle_check_and_report_errors(vdf_result)
  {
    if (vcf::is_error(vdf_result))
      exit(0, "Exiting plugin due to a VDF error: " + vdf_result.message);
    else
      exit(0, "Exiting plugin successfully.");
  }

  ##
  # Determine the vuln check path that needs to be taken based on the 
  # spec version provided then execute that path. 
  #
  # @param [vuln_data:array]  a "vuln_data" object, i.e. an array adhering to the vuln_data schema
  ##
  function check_by_spec(vuln_data)
  {
    var spec_ver = vuln_data.metadata.spec_version;

    var vuln_check_func = VULN_CHECK_SPECS[spec_ver];
    if (!vuln_check_func)
      return new vcf::Error('Unsupported spec version provided: ' + serialize(spec_ver));

    var vuln_check_results = vuln_check_func(vuln_data:vuln_data);

    return vuln_check_results;
  }

  ## 
  # Should only be used once per plugin to avoid excessive forking.
  # Determines if there are checks in vuln_data that apply to
  # detected product installs and performs those checks appropriately.
  # Will branch (i.e. fork) for every detected product's install.
  #
  # @param [vuln_data:array]          a "vuln_data" object, i.e. an array adhering to the vuln_data schema
  #
  # @return [check_result|vcf::Error|None] returns a vcf::Error if one was thrown, exits if no relevant products are installed,
  #                                        otherwise, returns a "check_result" object, with attributes:
  #                                        result, check, install, constraint, error                
  ##
  function vuln_check_v1(vuln_data)
  {
    # top-level requirements evaluation
    var top_level_req_met = requires_met(requires:vuln_data.requires);
    if (!top_level_req_met.success)
    {
      return handle_unmet_requirements(
        error:top_level_req_met.error, 
        ret:{result:"SAFE", check:NULL, install:NULL, constraint:NULL},
        log_msg:'The top-level requirements were not met: ' + serialize(vuln_data.requires),
        log_lvl:2
      );
    }

    # get unique product names from checks
    var products = get_products(checks:vuln_data.checks);
    if (empty_or_null(products))
      return new vcf::Error('No products were extracted from the vuln_data object.');
    dbg::detailed_log(lvl:4, msg:'Extracted products: ' + serialize(products));

    # get installs from the KB for each product name
    var installs = get_product_installs(products:products);
    # If installs is empty, it means no installed products matched the vuln data
    if (empty_or_null(installs))
      exit(0, 'No relevant products are installed');
    dbg::detailed_log(lvl:4, msg:'Found installs: ' + serialize(installs));

    # fork execution to a separate thread per install found
    var install = branch(installs);

    # from here on we're operating in a separate thread => code as if dealing with a single install
    dbg::detailed_log(lvl:4, msg:'Forked install: ' + serialize(install));

    if (install.version == UNKNOWN_VER)
      audit(AUDIT_UNKNOWN_APP_VER, install.product);

    # get the checks that:
    # (1) apply to the install's product and (2) pass check-level requirement evaluation
    var checks = get_applicable_checks(install:install, checks:vuln_data.checks);
    if (empty_or_null(checks))
    {
      if (!isnull(install.display_version) && !isnull(install.path))
        audit(AUDIT_INST_PATH_NOT_VULN, install.product, install.display_version, install.path);
      else if (!isnull(install.display_version))
        audit(AUDIT_INST_PATH_NOT_VULN, install.product, install.display_version);
      else
        audit(AUDIT_INST_PATH_NOT_VULN, install.product);
    }
    dbg::detailed_log(lvl:4, msg:install.product + ' has applicable checks: ' + serialize(checks));

    # finally evaluate the applicable checks against the install
    var check_result = eval_checks(checks:checks, install:install);

    return check_result;
  }

  ##
  # Determine if we have detected a version of a product that matches the vulnerable data provided in vuln_data
  #
  # @param [vuln_data:array] a tvdling_nasl vuln data object
  # @param [severity:int] global constant that defines the severity of this vulnerability
  #
  # @return check_results array containing the standardized input to report_results->unpatched_report
  #         or a vcf::Error if one was thrown
  ##
  function package_vuln_check_v1(vuln_data, severity)
  {
    # top-level requirements evaluation
    var top_level_req_met = requires_met(requires:vuln_data.requires);
    if (!top_level_req_met.success)
    {
      return handle_unmet_requirements(
        error:top_level_req_met.error, 
        ret:{result:"SAFE", check:NULL, install:NULL, constraint:NULL},
        log_msg:'The top-level requirements were not met: ' + serialize(vuln_data.requires),
        log_lvl:2
      );
    }
    
    dbg::detailed_log(lvl:1, msg:"Running Package Manager Vuln Checks");

    # If no package data is present we can stop running checks
    var package_manager_content = get_package_manager_content();
    if (empty_or_null(package_manager_content))
    {
      return new vcf::Error('no package managers install data present');
    }

    # If no package managers match we can stop running checks
    var matching_package_manager_checks = get_matching_package_manager_checks(vuln_data:vuln_data, pm_type:package_manager_content.type);
    if (empty_or_null(matching_package_manager_checks))
    {
      return new vcf::Error('no checks match the package manager in use');
    }

    var check_results = run_package_manager_checks(
      checks:matching_package_manager_checks, 
      installs:package_manager_content,
      report_type:get_report_type(vuln_data:vuln_data)
    );
    
    check_results["product"] = package_manager_content.type;

    return check_results;
  }

  ##
  # Gather RPM or DPKG install data
  # 
  # @remark We should not run into a case where both of these are hit, 
  #     this function depends on get_package_data() call which returns 
  #     the first package manager it hits in the list that had data)
  #
  # @return an array containing package type and packages or NULL if none found
  ##
  function get_package_manager_content()
  {
    dbg::detailed_log(lvl:1, msg:"get package manager content.");

    # This will only ever return one package manager, if RPM and DPKG are present then only RPM will get returned    
    var package_data = package_manager_utils::get_package_data();
    dbg::detailed_log(lvl:4, msg:'get_package_data : \n'+ serialize(package_data)); 
    if (empty_or_null(package_data)) return package_data;

    # convert to the TVDLing nasl formart for package names
    if (package_data.type == "rpm")
      package_data.type =  "rpm_package";
    else if (package_data.type == "deb")
      package_data.type =  "dpkg_package";
    else
      package_data = NULL;

    dbg::detailed_log(lvl:3, msg:'package_data.type : '+ package_data.type); 
    return package_data;
  }

  ##
  # If RPM then pull all the rpm_package checks, if DPKG pull all the dpkg_package checks
  #
  # @param [vuln_data:array] the calling plugins vuln_data spec
  # @param [pm_type:string] the patch management type string matching the spec
  #
  # @return list of checks relevant to the patch management type
  ##
  function get_matching_package_manager_checks(vuln_data, pm_type)
  {
    dbg::detailed_log(lvl:1, msg:"get matching package checks for " + pm_type);

    # Build a new list of checks that only contain the type that matches pm_type
    var checks_that_match_package = [];
    foreach var check (vuln_data.checks)
    {
      if (check.product.type == pm_type)
      {
        append_element(value:check, var:checks_that_match_package);
      }
    }

    dbg::detailed_log(lvl:4, msg:'Matching Package Checks : \n'+ serialize(checks_that_match_package));
    dbg::detailed_log(lvl:3, msg:'Number of Matching Package Checks : '+ max_index(checks_that_match_package));

    return checks_that_match_package;
  }

  ##
  # Iterate over installed package and check, 
  # if install product matches check product run the checks
  # (right now this is just unpatched but we need to leave room for rpm.inc and dpkg.inc to be called)
  # set the report type flag to unpatched if the checks are unpatched checks
  # 
  # @param [checks:list] the relevant checks that need to be ran
  # @param [installs:list] list of packages installed on the system
  # @param [report_type:string] the value in vuln_data.report.report_type if present
  #
  # @return list containing the results for each check
  ##
  function run_package_manager_checks(checks, installs, report_type)
  {
    dbg::detailed_log(lvl:1, msg:"Running package manager checks.");

    var current_check_report_type = report_type;
    var res, unpatched_data, check_results, check_req;
    var results = [];
    foreach var check (checks)
    {
      check_req = requires_met(requires:check.requires);
      if (!check_req.success)
      {
        handle_unmet_requirements(
          error:check_req.error, 
          ret:NULL,
          log_msg:'The check requirements were not met: ' + serialize(check.requires),
          log_lvl:3
        );
        continue;
      }
      dbg::detailed_log(lvl:3, msg:"Requirements met for check " + serialize(check));
      

      # set report type for this check to determine if this is unpatched or typical check
      if (!empty_or_null(check.report.report_type)) current_check_report_type = check.report.report_type;
      else current_check_report_type = report_type;

      if (current_check_report_type == "unpatched") 
      {
        dbg::detailed_log(lvl:3, msg:"Check Type Is 'Unpatched'");
        foreach var install (installs.packages)
        {
          if (typeof(check.product.name) == "string")
          {
            dbg::detailed_log(lvl:4, msg:"Check.product.name:"+check.product.name + " == install.properties.name:" + install.properties.name);
            if (check.product.name != install.properties.name) continue;
            dbg::detailed_log(lvl:3, msg:"Check matched install :" + check.product.name +"=="+install.properties.name);
            check_unpatched_constraints(install:install, check:check, results:results);
          }
          else if (typeof(check.product.name) == "array")
          {
            foreach var product_name (check.product.name)
            {
              dbg::detailed_log(lvl:4, msg:"Check.product.name:"+product_name + " == install.properties.name:" + install.properties.name);
              if (product_name != install.properties.name) continue;
              dbg::detailed_log(lvl:3, msg:"Check matched install :" + product_name +"=="+install.properties.name);
              check_unpatched_constraints(install:install, check:check, results:results);
            }
          }
        }
      }
      else
      {
        # In this section we need to run a version check. 
        # This is not currently implimented 
        var msg = "We encountered a package manger check that is not categoried as unpatched."+
        "This is currently not supported in vdf checks and should use traditional check methods at this time.";
        dbg::detailed_log(lvl:1, msg:msg);
        continue;
      }
    }

    if (max_index(results) > 0)
    {
      dbg::detailed_log(lvl:1, msg:"VULN");
      check_results = {
        result:"VULN",
        check:NULL,
        install:results,
        constraint:NULL
      };
    }
    else
    {
      dbg::detailed_log(lvl:1, msg:"SAFE");
      check_results = {
        result:"SAFE",
        check:NULL,
        install:results,
        constraint:NULL
      };
    }

    dbg::detailed_log(lvl:3, msg:'Check Results : \n'+ serialize(check_results));

    return check_results;
  }

  ##
  # Check constraints and anything that matches add it to the results array
  # 
  # @param [install:array] pass by reference of the installed package data
  # @param [check:array] pass by reference of the check values
  # @param [results:list] pass by reference of the results of findings
  #
  # @return NULL the data is added to the results reference parameter
  ##
  function check_unpatched_constraints(&install, &check, &results)
  {
    var constraint_req;

    foreach var constraint (check.constraints)
    {
      dbg::detailed_log(lvl:4, msg:"Running Constraint : " + serialize(constraint));

      constraint_req = requires_met(requires:constraint.requires);
      if (!constraint_req.success)
      {
        handle_unmet_requirements(
          error:constraint_req.error, 
          ret:NULL,
          log_msg:'The constraint requirements were not met: ' + serialize(constraint.requires),
          log_lvl:3
        );
        continue;
      }

      # all requirements met, unpatched does not have version checks, we can report this as unpatched
      var unpatched_data = {"name":install.properties.name, "version":install.properties.version};
      dbg::detailed_log(lvl:2, msg:"add to unpatched report : " + serialize(unpatched_data));
      append_element(value:unpatched_data, var:results);
      break;
    }
  }

  ## 
  # Evaluates the applicable checks for an install using the appropriate
  # version check algorithm and returns a VULN or SAFE check result.
  #
  # @param [checks:list]    a list of "check objects", i.e. a vuln check definition that includes
  #                         the product to check, the check algorithm to use, scan/host/install 
  #                         requirements and version constraints to check against, reporting parameters
  #
  # @return [check_result]  returns a "check_result" object, with attributes:
  #                         result, check, install, constraint, error
  ##
  function eval_checks(checks, install)
  {
    # apply specified check algorithm to applicable constraints
    var check, constraint, result, check_req;
    var check_result = {result:'SAFE', check:NULL, install:install, constraint:NULL, error:NULL};

    foreach check (checks)
    {
      # before evaluating constraints, parse the install's version
      # POST-MERGE: use check.version_parser to decouple from check_algorithm
      install.parsed_version = apply_version_parser(parser:check.check_algorithm, version:install.version);
      if (vcf::is_error(install.parsed_version))
      {
        check_result.result = 'ERROR';
        check_result.error = install.parsed_version;
        return check_result;
      }

      # loop through check's constraints and check each one
      foreach constraint (check.constraints)
      {
        # first check constraint's requirements
        check_req = requires_met(requires:constraint.requires, install:install);
        if (!check_req.success)
        {
          handle_unmet_requirements(
            error:check_req.error, 
            ret:NULL,
            log_msg:'The constraint requirements were not met: ' + serialize(constraint.requires),
            log_lvl:3
          );
          continue;
        }

        # then evaluate the constraint using the check's algorithm
        result = apply_check_algorithm(
          algorithm:check.check_algorithm,
          constraint:constraint,
          install:install
        );
        
        # bubble error up
        if (vcf::is_error(result))
        {
          check_result.result = 'ERROR';
          check_result.error = result;
          return check_result;
        }
        # found a vuln constraint/check, skip the rest and return the result
        else if (result == 'VULN')
        {
          # store relevant data for the vuln result
          check_result.result = result;
          check_result.constraint = constraint;
          check_result.check = check;
          # we reached a vuln result, skip other constraints/checks and return
          return check_result;
        }
      }
    }

    # if we reached this point, no vuln constraints were found in any check
    # thus the current install is safe/not affected
    return check_result;
  }

  ## 
  # Calls the appropriate version parser based on the parser name provided.
  #
  # @param [parser:string]    the name of the version parser to use, can be empty/NULL
  # @param [version:string]   the pristine detected version to be parsed
  #
  # @return [list|vcf::Error] returns the parsed version in a nested list of version segments
  #                           or returns a vcf::Error if one was thrown
  ##
  function apply_version_parser(parser, version)
  {
    var version_parser;

    if (empty_or_null(parser))
      version_parser = @default_parser;
    else
    {
      version_parser = VERSION_PARSERS[parser];
      if (!version_parser)
      {
        dbg::detailed_log(lvl:1, msg:'Unsupported version parser provided: ' + serialize(version_parser));
        return new vcf::Error('Unsupported version parser provided: ' + serialize(version_parser));
      }  
    }

    var parsed_version = version_parser(version:version);

    return parsed_version;
  }

  ## 
  # Parses the provided version using vcf::parse_version() and returns the result.
  #
  # @param [version:string]   the pristine detected version to be parsed
  #
  # @return [list|vcf:Error]  returns the parsed version in a nested list of version segments
  #                           or returns a vcf::Error if one was thrown
  ##
  function default_parser(version)
  {
    if (empty_or_null(version))
      return vcf::arg_error(arg:"version", func:FUNCTION_NAME);

    var parsed_version = vcf::parse_version(version);
    if (vcf::is_error(parsed_version))
    {
      dbg::detailed_log(lvl:1, msg:'Version parsing error: ' + serialize(parsed_version));
      return parsed_version;
    }

    return parsed_version;
  }

  ## 
  # Calls the appropriate version checking function based on the algorithm provided.
  #
  # @param [parser:string]      the name of the version checking func to use, can be empty/NULL
  # @param [constraint:string]  the constraint to check against during version checking
  # @param [install:array]      array containing install data for a product
  #
  # @return ['VULN'|'SAFE'|vcf::Error]  returns the outcome of the version check, or an error
  ##
  function apply_check_algorithm(algorithm, constraint, install)
  {
    var check_algo;

    if (empty_or_null(algorithm))
      check_algo = @default_check;
    else
    {
      check_algo = CHECK_ALGORITHMS[algorithm];
      if (!check_algo)
      {
        dbg::detailed_log(lvl:1, msg:'Unsupported check algorithm provided: ' + serialize(algorithm));
        return new vcf::Error('Unsupported check algorithm provided.');
      }  
    }

    var check_result = check_algo(constraint:constraint, install:install);

    return check_result;
  }

  # POST-MERGE: validate parity with current VCF checking, e.g. add managed/backport/paranoid logic
  ## 
  # Executes the default version checking algorithm between an install version and a constraint.
  # Parses the install version if it's parsed already.
  #
  # @param [constraint:array]           array with possible keys:
  #                                     requires, report, equal, min_version, max_version, fixed_version
  # @param [install:array]              array containing install data for a product
  # @param [strict:boolean]             boolean that determines strictness of check
  #
  # @return ['VULN'|'SAFE'|vcf::Error]  returns 'VULN' if the install version matches the constraint
  #                                     returns 'SAFE' if the install version does not match the constraint
  #                                     returns a vcf:Error if one was thrown
  ##
  function default_check(constraint, install, strict)
  {
    var parsed_version = install.parsed_version;
    if (empty_or_null(parsed_version) || typeof(parsed_version) != "array")
      return vcf::arg_error(arg:"install.parsed_version", func:FUNCTION_NAME);
    if (empty_or_null(constraint))
      return vcf::arg_error(arg:"constraint", func:FUNCTION_NAME);
    if (empty_or_null(strict))
      strict = false;

    var check_result = vcf::check_version_against_constraint(
      version:parsed_version,
      constraint:constraint,
      strict:strict
    );
    # bubble up any errors thrown
    if (vcf::is_error(check_result))
    {
      dbg::detailed_log(lvl:1, msg:'Error thrown by check_version_against_constraint: ' + serialize(check_result));
      return check_result;
    }

    # if the check_result is true, the outcome is VULN
    if (check_result)
      return 'VULN';
    
    return 'SAFE';
  }

  ## 
  # Filters the provided list of checks to only those that apply to the provided install and 
  # pass requirement evaluation.
  #
  # @param [install:array]  array containing install data for a product
  # @param [checks:list]    a list of "check objects", i.e. a vuln check definition that includes
  #                         the product to check, the check algorithm to use, scan/host/install 
  #                         requirements and version constraints to check against, reporting parameters
  #
  # @return [list]          list of applicable checks
  ##
  function get_applicable_checks(install, checks)
  {
    var check_req;
    var applicable_checks = [];
    foreach var check (checks)
    {
      # if the check does not concern the forked install's product, skip the check
      if (install.product != check.product.name)
        continue;
      
      # if the check-level requirement is not met, skip the check
      check_req = requires_met(requires:check.requires, install:install);
      if (!check_req.success)
      {
        handle_unmet_requirements(
          error:check_req.error, 
          ret:NULL,
          log_msg:'The check requirements were not met: ' + serialize(check.requires),
          log_lvl:3
        );
        continue;
      }

      # this is an applicable check, store it
      append_element(value:check, var:applicable_checks);
    }
    
    return applicable_checks;
  }

  # POST-MERGE: finalize schema/input validation
  ## 
  # Calls the appropriate schema validator depending on spec version.
  #
  # @param [vuln_data:array]  a "vuln_data" object, i.e. an array adhering to the vuln_data schema
  #
  # @return [POST-MERGE]            POST-MERGE
  ##
  function valid_input_by_spec(vuln_data)
  {
    var spec_ver = vuln_data.metadata.spec_version;

    var valid_input_func = VALID_INPUT_SPECS[spec_ver];
    if (!valid_input_func)
      return new vcf::Error('Unsupported spec version provided: ' + spec_ver);

    var valid_input_results = valid_input_func(vuln_data:vuln_data);

    return valid_input_results;
  }
  
  # POST-MERGE: finalize schema/input validation
  ## 
  # Validates the vuln_data input according to the schema structure defined in spec v1.0
  #
  # @param [vuln_data:array]  a "vuln_data" object, i.e. an array adhering to the vuln_data schema
  #
  # @return [POST-MERGE]            POST-MERGE
  ##
  function valid_input_v1(vuln_data)
  {
    return true;
  }
  
  ##
  # When a requirement is not met this will handle if it was
  # because of an error or requirement truly not being met.
  # 
  # @param [error:vcf:error|NULL] the error value returned from requires_met()
  # @param [ret:any] what should be returned if this was not an error
  # @param [log_msg:string] detailed_log msg value if this was not an error
  # @param [lvl:int] the detailed_log lvl value if this was not an error
  #
  # @return ret value or vcf::error depending on the finding
  ##
  function handle_unmet_requirements(error, ret, log_msg, log_lvl)
  {
    if (!isnull(error))
      return error;

    dbg::detailed_log(lvl:log_lvl, msg:log_msg);
    return ret; 
  }

  ## 
  # Examines and evaluates each requirement provided. If all requirements pass, i.e. evaluate to true,
  # it returns true, otherwise returns false.
  #
  # @param [requires:list]  a list of "requirement"/"require" objects, each being an array that contains:
  #                         a scope key and any number of operator keys e.g. match, not_match, etc.
  # @param [install:array]  array containing install data for a product
  # 
  # @return [object]        returns an object with keys "success" and "error"
  #                         "success" is true/false depending on requirement resolution
  #                         if "success" is true, then "error" is NULL, otherwise "error" is a vcf::Error
  ##
  function requires_met(requires, install)
  {
    if (empty_or_null(requires))
      return {"success":true, "error":NULL};
    if (typeof_ex(requires) != 'list')
    {
      var error = 'Schema error: cannot process requires object of type ' + serialize(typeof_ex(requires)) +
                  '. It must be a list.';
      dbg::detailed_log(lvl:1, msg:error);
      return {"success":false, "error":error};
    }

    var req_met, property;

    # POST-MERGE: allow passing a single requirement array, instead of always providing a list
    
    foreach var req (requires)
    {
      if (empty_or_null(req))
      {
        dbg::detailed_log(lvl:1, msg:'Schema error: requirement is empty or null');
        continue;
      }
      
      # infer the scope if missing
      if (empty_or_null(req.scope))
      {
        # if we don't have an install, this is a top-level req and scope is 'target' implicitly
        if (empty_or_null(install))
          req.scope = 'target';
        # if we have an install, this is a check/constraint-level req and scope is 'install' implicitly
        else
          req.scope = 'install';
      }
        
      dbg::detailed_log(lvl:4, msg:'Evaluating requirement: ' + serialize(req));

      # evaluate the current requirement and return the outcome
      req_met = eval_req(req:req, install:install);
      if (vcf::is_error(req_met))
      {
        dbg::detailed_log(lvl:1, msg:"An error occurred during requirement evaluation: " + req_met.message);
        return {"success":false, "error":req_met};
      }
      # if the current requirement is not met, the entire requires object is not met
      # we should stop checking the rest and return false      
      if (!req_met)
        return {"success":false, "error":NULL};
    }

    return {"success":true, "error":NULL};
  }

  ## 
  # Evaluates the provided requirement according to its scope and returns the outcome of the evaluation.
  #
  # @param [req:array]                a "requirement"/"require" object, i.e. an array whose possible keys are
  #                                   a scope key and any number of operator keys e.g. match, not_match, etc.
  # @param [install:array]            array containing install data for a product
  # 
  # @return [boolean|vcf::Error]      returns true/false depending on evaluation outcome
  #                                   returns a vcf::Error if one was thrown
  ##
  function eval_req(req, install)
  {
    var conditions, cond_value, value, result;
    foreach var operator (keys(req))
    {
      if (operator == 'scope') continue;

      conditions = req[operator];
      dbg::detailed_log(lvl:2, msg:'Evaluating requirement conditions: ' + serialize(conditions));

      foreach var cond_property (keys(conditions))
      {
        cond_value = conditions[cond_property];
        dbg::detailed_log(msg:'condition: ' + obj_rep(cond_property) + ':' + obj_rep(cond_value));

        if (req.scope == 'target' || req.scope == 'scan_config')
          value = eval_target_property(property:cond_property);
        else
          value = eval_install_property(property:cond_property, install:install);
      
        # if the property isn't found or an error occurred, value should be NULL or vcf:Error
        if (vcf::is_error(value))
        {
          dbg::detailed_log(lvl:1, msg:"An error occurred during evaluation of property: " + serialize(cond_property));
          return value;
        }

        result = apply_operator(left_operand:value, right_operand:cond_value, operator:operator);
        # if the operation evals to false
        # then the requirement is not met, we should stop here and return false
        if (!result)
          return false;
      }
    }

    return true;
  }

  ## 
  # Evaluates the provided install property using the provided install object.
  #
  # @param [property:string]        install property to evaluate
  # @param [install:array]          array containing install data for a product
  # 
  # @return [anything|vcf::Error]   returns the value of the property as a key in the install array
  #                                 or vcf::Error if said value is empty or NULL
  ##
  function eval_install_property(property, install)
  {
    if (empty_or_null(install[property]))
    {
      dbg::detailed_log(lvl:1, msg:'The following install property was found empty or NULL: ' + serialize(property));
      return new vcf::Error('The following install property was found empty or NULL: ' + serialize(property));
    }

    return install[property];
  }

  ## 
  # Evaluates the provided target property using the appropriate property translator.
  #
  # @param [property:string]        target property to evaluate
  # 
  # @return [anything|vcf::Error]   returns the value of the property as translated by a property translator
  #                                 returns a vcf::Error if one was thrown due to a translation error or due
  #                                 to receiving a property that does not have a corresponding translator
  ##
  function eval_target_property(property)
  {
    # get the right translator function for the passed property, if it exists
    var property_translator = PROPERTY_TRANSLATORS[property];
    if (!property_translator)
    {
      dbg::detailed_log(lvl:1, msg:'Unsupported requires property provided: ' + serialize(property));
      return new vcf::Error('Unsupported requires property provided: ' + serialize(property));
    }

    var target_value = property_translator();
    # translation failed, error handle this
    if (isnull(target_value))
    {
      dbg::detailed_log(lvl:1, msg:'An error occurred translating property: ' + serialize(property));
      return new vcf::Error('An error occurred translating property: ' + serialize(property));
    }

    return target_value;
  }

  ##
  # Get the vendor unpatched scan configuration value
  #
  # @return the value of the vendor unpatched scan config 
  ##
  function get_vendor_unpatched_scan_config()
  {
      var vendor_unpatched = get_kb_list("global_settings/vendor_unpatched");
      dbg::detailed_log(lvl:3, msg:"Scan_config vendor_unpatched = " + serialize(vendor_unpatched));
      if (isnull(vendor_unpatched)) return false;
      return true;
  }

  ## 
  # Property translator for the "paranoia" target property
  #
  # @return the report_paranoia global variable
  ##
  function get_paranoia()
  {
    return report_paranoia;
  }

  ## 
  # Property translator for the "os" target property
  #
  # @return [string|NULL]   returns a string for an OS depending on the KB entries found
  #                         returns NULL if the OS could not be determined
  ##
  function get_os()
  {
    dbg::detailed_log(lvl:2, msg:'Translating os property.');
    
    var smb_reg_enumerated = get_one_kb_item('SMB/Registry/Enumerated');
    var host_uname = get_one_kb_item('Host/uname');
    var macosx_version = get_one_kb_item('Host/MacOSX/Version');

    dbg::detailed_log(lvl:3, msg:"SMB/Registry/Enumerated = " + serialize(smb_reg_enumerated));
    dbg::detailed_log(lvl:3, msg:"Host/uname = " + serialize(host_uname));
    dbg::detailed_log(lvl:3, msg:"Host/MacOSX/Version = " + serialize(macosx_version));
    
    if (smb_reg_enumerated)
      return 'windows';
    else if (host_uname && isnull(macosx_version))
      return 'linux';
    else if (macosx_version)
      return 'macos';
  
    return NULL;
  }

  ## 
  # Linux "distro" property translation helper. Provides the Linux distro and release info found in the KB
  #
  # @return [array|NULL] returns NULL if no release KB is found, otherwise returns the distro name and release info
  ##
  function get_linux_release_info()
  {
    var release_kb_list = get_kb_list('Host/*/release');
    if (empty_or_null(release_kb_list))
      return NULL;
    
    var release_kb_keys = keys(release_kb_list);
    var release_kb_name = release_kb_keys[0];
    var release_value = release_kb_list[release_kb_name];

    # split the kb name to get the distro, e.g. 'RedHat' from 'Host/RedHat/release'
    var kb_name_parts = split(release_kb_name, sep:"/", keep:false);
    var distro = tolower(kb_name_parts[1]);

    var release_info = {'distro': distro, 'release': release_value};

    return release_info;
  }

  ## 
  # Property translator for the "distro" target property
  #
  # @return [string|NULL] a string for a distro depending on the KB entries found
  ##
  function get_distro()
  {
    dbg::detailed_log(lvl:2, msg:'Translating distro property.');

    var release_info = get_linux_release_info();
    if (empty_or_null(release_info))
      return NULL;

    var distro = release_info.distro;
    var release = release_info.release;

    if (distro == 'redhat')
    {
      if (get_one_kb_item('Host/OracleLinux'))
        distro = "oracle";
      else if ('fedora' >< tolower(release))
        distro = 'fedora';
    }
    else if (distro == 'amazonlinux')
      distro = 'amazon';
    else if (distro == 'almalinux')
      distro = 'alma';
    else if (distro == 'rockylinux')
      distro = 'rocky';
    else if (distro == 'centos')
    {
      if ('stream' >< tolower(release))
        distro = 'centos-stream';
    }
    else if (distro == 'suse')
    {
      var matches = pregmatch(pattern:'^SLE(S|D)(?:_SAP)?(\\d+)', string:release);
      if (!empty_or_null(matches))
      {
        if (matches[1] == "S")
          distro = 'suse-server';
        else if (matches[1] == "D")
          distro = 'suse-desktop';
      }
      else
      {
        matches = pregmatch(pattern:'^SUSE(\\d+)(?:\\.(\\d+))', string:release);
        if (!empty_or_null(matches))
          distro = 'opensuse';
      }
    }
  
    return distro;
  }

  ## 
  # Property translation helper for the Linux "os_version"
  #
  # @return [string|NULL] returns a string for the linux OS version depending on the KB entries found
  #                       returns NULL if the OS isn't linux or if distro/release info wasn't found
  ##
  function get_linux_version()
  {
    # get linux distro name and release info
    var release_info = get_linux_release_info();
    if (empty_or_null(release_info))
      return NULL;

    var distro = get_distro();
    var release = release_info.release;
    if (empty_or_null(distro) || empty_or_null(release))
      return NULL;

    var version, matches;
    if (distro == 'fedora')
    {
      matches = pregmatch(pattern: '^fedora.*release ([0-9]+)', string:release, icase:true);
      if (!empty_or_null(matches))
        version = 'FC' + default_if_empty_or_null(matches[1], default:'0');
    }
    else if (distro == 'centos' || distro == 'centos-stream')
    {
      matches = pregmatch(pattern: '^CentOS (?:Stream )?(?:Linux )?release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:true);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[1], default:'0');
    }
    else if (distro == 'ubuntu')
    {
      matches = pregmatch(pattern: '^(\\d[\\d\\.]+)', string:release, icase:true);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[1], default:'0');
    }
    else if (distro == 'redhat')
    {
      matches = pregmatch(pattern: '^Red Hat Enterprise Linux.*release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:true);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[1], default:'0');
    }
    else if (distro == 'alma')
    {
      matches = pregmatch(pattern: '^AlmaLinux release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:true);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[1], default:'0');
    }
    else if (distro == 'rocky')
    {
      matches = pregmatch(pattern: '^Rocky Linux release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:true);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[1], default:'0');
    }
    else if (distro == 'debian')
    {
      matches = pregmatch(pattern: '^(\\d+)(?:\\.(\\d+))?', string:release, icase:true);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[1], default:'0');
    }
    else if (distro == 'oracle')
    {
      matches = pregmatch(pattern: '^Oracle (?:Linux Server|Enterprise Linux) .*release (\\d+)(?:\\.(\\d+))?', string:release, icase:true);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[1], default:'0');
    }
    else if (distro == 'amazon')
    {
      matches = pregmatch(pattern: '^AL(A|\\d|-2023)', string:release);
      if (!empty_or_null(matches) && !empty_or_null(matches[1]))
      {
        if(matches[1] == "A")
          version = "amzn1";
        else if (matches[1] == "2")
          version = "amzn2";
        else if (matches[1] == "-2023")
          version = "amzn2023";
      }
    }
    else if (distro == 'suse-server' || distro == 'suse-desktop')
    {
      matches = pregmatch(pattern: '^SLE(S|D)(?:_SAP)?(\\d+)', string:release);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[2], default:'0');
    }
    else if (distro == 'opensuse')
    {
      matches = pregmatch(pattern: '^SUSE(\\d+)(?:\\.(\\d+))', string:release);
      if (!empty_or_null(matches))
        version = default_if_empty_or_null(matches[1], default:'0');
    }

    return version;
  }

  ## 
  # Property translator for the "os_version" target property
  #
  # @return [string|NULL] returns a string for the OS version depending on the KB entries found
  #                       returns NULL if the OS translator couldn't determine the OS
  ##
  function get_os_version()
  {
    dbg::detailed_log(lvl:2, msg:'Translating os_version property.');

    var os = get_os();
    if (empty_or_null(os)) 
      return NULL;

    var os_ver;
    if (os == 'windows')
      os_ver = get_one_kb_item('SMB/WindowsVersion');
    else if (os == 'linux')
      os_ver = get_linux_version();
    else if (os == 'macos')
      os_ver = get_one_kb_item('Host/MacOSX/Version');

    return os_ver;
  }

  ## 
  # Applies the provided operator between two operands.
  #
  # @return [boolean]   returns true if the outcome of the operation is true
  #                     returns false if the outcome is false, or if
  #
  # Note: the supported operators are [match, match_one, not_match, regex_match, not_regex_match, greater_or_eq,
  #                                     less_or_eq, greater, less, contains, not_contains]
  ##
  function apply_operator(left_operand, right_operand, operator)
  {
    dbg::detailed_log(
      lvl:2,
      msg:'Operation: ' + serialize(left_operand) + ' ' + serialize(operator) + ' ' + serialize(right_operand)
    );

    switch (operator)
    {
      case 'match':
        if (left_operand == right_operand) return true;
        break;
      case 'match_one':
        if (typeof_ex(right_operand) == 'list')
        {
          foreach var list_item (right_operand)
            if (left_operand == list_item) return true;
        }
        else
          dbg::detailed_log(lvl:1, msg:'Schema error: operator match_one applied to non-list right-operand');
        break;
      case 'not_match':
        if (left_operand != right_operand) return true;
        break;
      case 'regex_match':
        if (left_operand =~ right_operand) return true;
        break;
      case 'not_regex_match':
        if (left_operand !~ right_operand) return true;
        break;
      case 'greater_or_eq':
        if (left_operand >= right_operand) return true;
        break;
      case 'less_or_eq':
        if (left_operand <= right_operand) return true;
        break;
      case 'greater':
        if (left_operand > right_operand) return true;
        break;
      case 'less':
        if (left_operand < right_operand) return true;
        break;
      case 'contains':
        if (left_operand >< right_operand) return true;
        break;
      case 'not_contains':
        if (left_operand >!< right_operand) return true;
        break;
    }

    return false;
  }

  ## 
  # Retrieves the top-level report type from the vuln_data object provided.
  #
  # @param [vuln_data:array]    a "vuln_data" object, i.e. an array adhering to the vuln_data schema
  # @return [string]            returns the top-level report type if one is found, otherwise returns 'default'
  #
  ##
  function get_report_type(vuln_data)
  {
    if (empty_or_null(vuln_data) || empty_or_null(vuln_data.report) || empty_or_null(vuln_data.report.report_type))
      return 'default';

    return vuln_data.report.report_type;
  }

  ## 
  # Extracts unique product names from provided checks and adds them to lists categorized by product type.
  #
  # @param [checks:list]    a list of "check objects", i.e. a vuln check definition that includes
  #                         the product to check, the check algorithm to use, scan/host/install 
  #                         requirements and version constraints to check against, reporting parameters
  #
  # @return [array]         an array containing lists of products, keyed by product type
  #
  ##
  function get_products(checks)
  {
    # array of sets, one set per product type found
    var products = {};

    foreach var check (checks)
    {
      if (!empty_or_null(check.product))
      {
        # if we dont have a set for this product type already, create one
        if (!products[check.product.type])
          products[check.product.type] = collib::make_set();
        
        # add the product to its respective set
        products[check.product.type].insert(check.product.name);
        dbg::detailed_log(lvl:2, msg:'Storing product extracted from checks: ' + serialize(check.product));
      }
    }

    # loop through sets and convert them to lists
    foreach var product_type (keys(products))
      products[product_type] = products[product_type].to_list();

    return products;
  }
  
  # POST-MERGE: bring to parity with VCF install retrieval
  # Retrieves install data from the KB for the provided products
  # Note: product install data must be stored in the KB with register_install
  #
  # @param [products:array]   an array of products, keys being product types and values being lists of product names
  #
  # @return [list]            a list of arrays, each array containing a single product's install data
  #
  ##
  function get_product_installs(products)
  {
    var found_installs = [];
    var installs, install, product;

    # loop through product lists, currently should only handle product_type=='app'
    foreach var product_type (keys(products))
    {
      # loop through products in current product list
      foreach product (products[product_type])
      {
        installs = get_combined_installs(app_name:product);
        # installs[0] is IF_OK for a successful retrieval
        if (installs[0] == IF_OK)
        {
          foreach install (installs[1])
          {
            install.product = product;
            append_element(value:install, var:found_installs);
          }
        }
        else
        {
          dbg::detailed_log(lvl:2, msg:'No installs found for product: ' + serialize(product) + ', continuing');
          continue;
        }
      }
    }

    return found_installs;
  }

  # Given a vulnerable constraint/install pair, it assembles the report data required to create the text/message
  # that appears in the final report.
  # By default, the attributes gathered for reporting are:
  # the installed version, the fixed version, the report.cves if any are provided and one of: URL/Source/Path
  #
  # @param [check_result:array] an array containing data relevant to the check performed
  #                             it is expected to contain attributes: result, check, install, constraint, error
  #
  # @return [object]            data necessary to produce the final report text/message
  #
  ##
  function build_report_data(constraint, install)
  {
    # initialize version, fix and port
    var fix = constraint.fixed_display;
    if (empty_or_null(fix))
      fix = constraint.fixed_version;

    var version = install.display_version;
    if (empty_or_null(install.display_version))
      version = install.version;

    var report_port = install.port;
    if (empty_or_null(report_port))
      report_port = 0;

    # initialize default report items and order
    var report_items = {'Installed version': version, 'Fixed version': fix};
    var report_order = ['Installed version', 'Fixed version'];

    # prepend URL/Source/Path to the report if available
    if (install.webapp)
    {
      report_items['URL'] = build_url2(qs:install.path, port:report_port);
      insert_element(var:report_order, idx:0, value:'URL'); 
    }
    else if (!empty_or_null(install.source))
    {
      report_items['Source'] = install.source;
      insert_element(var:report_order, idx:0, value:'Source'); 
    }
    else if (!empty_or_null(install.path))
    {
      report_items['Path'] = install.path;
      insert_element(var:report_order, idx:0, value:'Path'); 
    }

    # append CVEs to the report if available
    if (!empty_or_null(constraint.report) && !empty_or_null(constraint.report.cves))
    {
      report_items['CVE(s)'] = '';
      foreach var cve (constraint.report.cves)
        report_items['CVE(s)'] += cve + ' ';
      append_element(var:report_order, value:'CVE(s)');
    }

    var report = {
      'items': report_items,
      'order': report_order, 
      'port': report_port,
      'proto': install.proto
    };

    dbg::detailed_log(lvl:2, msg:'Built report data: ' + serialize(report));

    return report;
  }

  # POST-MERGE: bring to parity with VCF reporting
  # Performs the default reporting workflow to report the outcome of a check result
  # If the check result is SAFE, it audits out with an appropriate message
  # If the check result is VULN, it first assembles the report data and then creates the actual text for the report
  #
  # @param [check_result:array] an array containing data relevant to the check performed
  #                             it is expected to contain attributes: result, check, install, constraint, error
  #
  # @return [object]            a report object containing the actual report text which can be NULL if an error occurred
  #                             also contains other report-related data
  #
  ##
  function default_report(check_result)
  {
    var install = check_result.install;
    # check if result is SAFE, audit out
    if (check_result.result == "SAFE")
    {
      if (!empty_or_null(install))
      {
        if (!isnull(install.version))
          audit(AUDIT_INST_VER_NOT_VULN, install.product, install.version);
        else
          audit(AUDIT_INST_VER_NOT_VULN, install.product);
      }
      else
      {
        audit(AUDIT_HOST_NOT, 'affected');
      }
    }

    # result is VULN, generate report according to reporting type
    dbg::detailed_log(lvl:2, msg:'Building default report for check result: ' + serialize(check_result));

    # prepare the report data
    var report = build_report_data(
      constraint:check_result.constraint,
      install:install
    );

    # build the final report text
    report.text = report_items_str(
      report_items:report.items,
      ordered_fields:report.order
    );

    # error handling
    if (vcf::is_error(report.text))
      report.text = NULL;
    
    return report;
  }

  # Custom report builder for report_type == unpatched
  # 
  # @param [check_result:array] Contains the install data
  # @param [severity:int] global constant that defines the severity of this vulnerability
  # @param [flags:array] a list of flag values used in reporting
  #
  # @remark severity and flags are not used in this function but are present
  #   to conform to the callback format.
  #
  # @return report data containing {port:int, text:string} 
  ##
  function unpatched_report(check_result)
  {
    dbg::detailed_log(lvl:1, msg:"Building Unpatched Report");

    if (check_result.result == "SAFE")
    {
      audit(AUDIT_HOST_NOT, "affected");
    }

    var report = {};
    report.port = 0;
    report.text = "";
    foreach var install (check_result.install)
    {
      # format : Remote package installed : name-version
      report.text += 'Remote package installed : ' + install.name + '-' + install.version + '\n';
    }

    return report;
  }

  # Reports a check result using the appropriate report building handler, default or custom, as specified in 
  # the report.type found at the top level of the vuln_data object or in the check result's associated check.
  #
  # @param [top_level_report_type:string] a report type provided at the top level of the vuln_data object
  # @param [check_result:array]           an array containing data relevant to the check performed
  #                                       it also contains attributes: result, check, install, constraint, error
  # @param [severity:int]                 severity used in reporting
  # @param [flags:array]                  array of reporting flags (xss, sqli, xsrf)
  #
  # @return [true|vcf::Error]             returns true if no errors occurred, otherwise returns a vcf::Error
  #
  ##
  function report_result(top_level_report_type, check_result, severity, flags)
  {
    dbg::detailed_log(lvl:2, msg:'Reporting check result: ' + serialize(check_result));

    var report_type, report_builder, report;
    
    # if there is a check-level report type, use that
    if (!empty_or_null(check_result.check.report_type))
      report_type = check_result.check.report_type;
    # otherwise, use the top-level report type
    else
      report_type = top_level_report_type;

    # if no report type has been defined in either level, use the default report builder
    if (empty_or_null(report_type))
      report_builder = @default_report;
    # otherwise, try to get the matching report builder for the report type
    else
    {
      report_builder = REPORT_BUILDERS[report_type];
      if (!report_builder)
      {
        dbg::detailed_log(lvl:1, msg:'Unsupported report type provided: ' + serialize(report_type));
        return new vcf::Error('Unsupported report type provided: ' + serialize(report_type));
      }
    }
    
    report = report_builder(check_result:check_result);
    if (empty_or_null(report) || empty_or_null(report.text) || empty_or_null(report.port))
    {
      dbg::detailed_log(lvl:1, msg:'Invalid constructed report: ' + serialize(report));
      return new vcf::Error('Invalid constructed report: ' + serialize(report));
    }

    security_report_v4(
      severity:severity,
      port:report.port,
      extra:report.text,
      xss:flags.xss,
      xsrf:flags.xsrf,
      sqli:flags.sqli,
      proto:report.proto
    );

    return true;
  }

}
