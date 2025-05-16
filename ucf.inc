###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# ucf.inc
#
# Revision: 1.11
###

include('compat_shared.inc');
include('cpes.inc');
include('debug.inc');
include('install_func.inc');
include('os_install.inc');
include('vcf.inc');
include('nessusd_product_info.inc');

#pragma static(include)
include('ucf_os.static');
#pragma static(include:false)


namespace ucf
{
  var TAP_MODE = FALSE;

  #####################
  # Primary Functions #
  #####################

  ##
  # Top funciton for first checking the version and date and then reporting on findings.
  #
  # @param [app_info:array]    Application info. requires, at minimum, a key/value pair for 'version'
  # @param [constraints:list]  List of constraint arrays
  # @param [severity:string]   Severity used for reporting
  # @param [hardware:list]     Hardware CPE list to be applied to all constraints (optional)
  #
  # @return [list] VCF exit call.
  #
  # @remark This funciton can potentiall audit out and exit plugin execution.
  ##
  function check_and_report(app_info, constraints, severity, hardware)
  {
    local_var matching_constraint, report_ver, hardware_check;

    if (empty_or_null(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
    if (empty_or_null(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
    if (empty_or_null(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

    # Check if we are on the correct hardware
    if (!empty_or_null(hardware))
    {
      hardware_check = vcf::check_for_hardware(cpes:hardware);
      if (vcf::is_error(hardware_check)) return vcf::vcf_exit(1, hardware_check.message);
      if (!hardware_check) return vcf::audit(app_info);
    }

    matching_constraint = check_version_date(app_info:app_info, constraints:constraints);
    if (vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

    if (!empty_or_null(matching_constraint))
      report_results(app_info:app_info, constraint:matching_constraint, severity:severity);
    # Audit
    else
      return vcf::audit(app_info);

    return vcf::vcf_exit(0);
  }

  #############
  # Reporting #
  #############

  ##
  # Builds the report, sets the unsupported tags, and calls security_report_v4 for plugin output.
  #
  # @param [app_info:array]   Applicaiton information
  # @param [constraint:array] Matching constraint information, needed for the date
  # @param [severity:string]  Severity level for reporting.
  #
  # @return [list] VCF exit call.
  ##
  function report_results(app_info, constraint, severity)
  {
    local_var report, version, port, parse_cpe, date;

    if (empty_or_null(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
    if (empty_or_null(constraint)) return vcf::arg_error(arg:"constraint", func:FUNCTION_NAME);
    if (empty_or_null(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);

    if (empty_or_null(app_info.display_version)) version = app_info.version;
    else version = app_info.display_version;

    report = build_report(app_info:app_info, constraint:constraint);
    if (vcf::is_error(report)) return vcf::vcf_exit(1, report.message);

    port = app_info.port;
    if (empty_or_null(port)) port = 0;

    parse_cpe = cpe_parse(cpe:app_info.cpe);
    if (vcf::is_error(parse_cpe)) return vcf::vcf_exit(1, report.message);

    register_unsupported_product(
        product_name  : app_info.app,
        version       : app_info.version,
        is_custom_cpe : parse_cpe[0],
        cpe_class     : parse_cpe[1],
        cpe_base      : parse_cpe[2]
      );

    security_report_v4(severity:severity, port:port, extra:report, proto:app_info.proto);
    return vcf::vcf_exit(0);
  }

  ##
  # Parses the Applicaiton CPE for better usage in register_unsupported_product()
  # 
  # @param [cpe:string] The CPE to be parsed
  #
  # @return [list] The parsed CPE or an error
  ##
  function cpe_parse(cpe)
  {
    local_var cpe_split, ret;

    if (empty_or_null(cpe)) return vcf::arg_error(arg:"cpe", func:FUNCTION_NAME);

    ret = make_list();

    cpe_split = split(cpe, sep:':', keep:FALSE);

    if ('x-' >< cpe_split[0])
      append_element(var:ret, value:TRUE);
    else
      append_element(var:ret, value:FALSE);

    if ('a' >< cpe_split[1])
      append_element(var:ret, value:CPE_CLASS_APPLICATION);
    else if ('o' >< cpe_split[1])
      append_element(var:ret, value:CPE_CLASS_OS);
    else if ('h' >< cpe_split[1])
      append_element(var:ret, value:CPE_CLASS_HARDWARE);
    else
      return new('vcf::Error', 'Error parsing cpe: "' + cpe + '" at : ' + cpe_split[1]);

    append_element(var:ret, value:cpe_split[2] + ':' + cpe_split[3]);

    return ret;
  }

  ##
  # Builds the string used in reporting output
  #
  # @param [app_info:array]   Applicaiton information
  # @param [constraint:array] Constraint information
  #
  # @return [string] The built plugin output string
  ##
  function build_report(app_info, constraint)
  {
    local_var order, report, report_items, seol_name, seol_ts, date;

    if(app_info.eseol && constraint.eseol)
    {
      seol_name = 'Extended Security End of Life';
      seol_ts = 'Time since Extended Security End of Life (Est.)';
      date = constraint.eseol;
    }
    else
    {
      seol_name = 'Security End of Life';
      seol_ts = 'Time since Security End of Life (Est.)';
      date = constraint.seol;
    }

    report_items[seol_name] = print_date(date:to_epoch(time:date+'000000'));
    report_items[seol_ts] = format_seconds_to_report(sec:constraint.time_since);

    # OS reporting
    if (!empty_or_null(app_info.os_name))
    {
      report_items['OS'] = app_info.os_name;
      order = ['OS', seol_name, seol_ts];

      return report_items_str(report_items:report_items, ordered_fields:order);
    }

    # Application reporting
    report_items['Installed version'] = app_info.version;
    order = ['Installed version', seol_name, seol_ts];

    if (app_info.webapp)
    {
      if (empty_or_null(app_info.port)) return vcf::arg_error(arg:'port', func:FUNCTION_NAME);
      report_items['URL'] = build_url2(qs:app_info.path, port:app_info.port);
      order = ['URL', 'Installed version', seol_name, seol_ts];
    }
    else if (!empty_or_null(app_info.source))
    {
      report_items['Source'] = app_info.source;
      order = ['Source', 'Installed version', seol_name, seol_ts];
    }
    else if(!empty_or_null(app_info.path))
    {
      report_items['Path'] = app_info.path;
      order = ['Path', 'Installed version', seol_name, seol_ts];
    }

    if (!empty_or_null(constraint.page))
    {
      report_items['Page'] = constraint.page;
      append_element(var:order, value:'Page');
    }

    return report_items_str(report_items:report_items, ordered_fields:order);
  }

  ###################################
  # Version checking and comparison #
  ###################################

  ##
  # Attempts to determine if the passed Applicaiton Information matches any of the vulnerability constraints.
  #
  # @param [app_info:array]   Applicaiton information
  # @param [constraints,list] List of vulnerability constraints
  #
  # @return [array] The matching constraint
  #         [list]  An error
  #         NULL    When no constraints match
  #
  # @remark This will exit if the verison is not granular enough for any contraint.
  ##
  function check_version_date(app_info, constraints)
  {
    local_var meets_constraint, constraint, date, gran;

    if (empty_or_null(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
    if (empty_or_null(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);
    if (isnull(app_info.parsed_version) || typeof(app_info.parsed_version) != "array")
      return vcf::arg_error(arg:"version", func:FUNCTION_NAME);

    foreach constraint (constraints)
    {
      meets_constraint = check_hardware_against_constraint(constraint:constraint);
      if (vcf::is_error(meets_constraint)) return meets_constraint;
      if (!meets_constraint) continue;

      meets_constraint = check_version_against_constraint(version:app_info.parsed_version, constraint:constraint);
      if (vcf::is_error(meets_constraint)) return meets_constraint;
      if (!meets_constraint) continue;

      if (app_info.eseol && constraint.eseol)
        meets_constraint = check_against_date(date:constraint.eseol);
      else
        meets_constraint = check_against_date(date:constraint.seol);

      if (vcf::is_error(meets_constraint)) return meets_constraint;
      if (meets_constraint)
      {
        constraint.time_since = meets_constraint;
        return constraint;
      }
    }

    return NULL;
  }

  ##
  # Determines if the current date is past the date.
  #
  # @param [date:string] A date in the format of "YYYYMMDD"
  #
  # @return [int] The number of seconds since the date has passed
  #         FALSE When the date is newer
  #
  # @remark We check the Feed date first as it is more reliable.
  ##
  function check_against_date(date)
  {
    local_var plugin_feed, unixtime, feedtime;

    if (empty_or_null(date) || typeof(date) != 'int') return vcf::arg_error(arg:'date', func:FUNCTION_NAME);

    date = to_epoch(time:date+'000000');

    plugin_feed = get_kb_item('PluginFeed/Version');
    if ('flat_' >< plugin_feed)
      plugin_feed -= 'flat_'; # Make flatline work
    feedtime = int(to_epoch(time:plugin_feed));

    if (TAP_MODE)
    {
      if (int(date) < feedtime)
        return feedtime - int(date);
      else
        return FALSE;
    }

    if (!empty_or_null(plugin_feed))
    {
      if (int(date) < feedtime)
        return feedtime - int(date);
    }
    # Check the scanner time
    unixtime = get_unixtime();
    if (int(date) < unixtime)
      return unixtime - int(date);

    return FALSE;
  }

  ##
  # Determines whether or not the detected hardware falls within a given constraint or not.
  # 
  # [constraint:array] list of applicable hardware CPE attribute constraints (e.g. [{ vendor: 'dell', product: 'rx7000' }, { vendor: 'dell', product: 'precision_7910' }])
  #
  # @return TRUE   If installed OS is within constraint
  #         FALSE  If installed OS is not within constraint
  #         [list] If an error occurred
  ##
  function check_hardware_against_constraint(constraint) {
    # If there is not OS constraint assume it is a valid OS
    if (empty_or_null(constraint.hardware))
      return TRUE;

    return vcf::check_for_hardware(cpes:constraint.hardware);
  }

  ##
  # Determines whether or not the provided version falls within the given constraint or not
  #
  # @param [version:string] Parsed version being checked
  # @param [constraint:array] Constraint with possible key/values for branch, min_branch, max_branch
  #
  # @return TRUE   If version within constraint
  #         FALSE  If version is not within constraint
  #         [list] if an error occurred
  #
  # @remark Has a granularity check that will return the audit.
  ##
  function check_version_against_constraint(version, constraint)
  {
    local_var cmp_result;

    # If an equality check is specified, nothing else is taken
    # into account. Check for an exact match.
    if (constraint.branch)
    {
      return compare_version_to_check(version:version, comparator:'=', cmp_ver:constraint.branch);
    }

    # Check that we meet a minimum version (if specified)
    if (constraint.min_branch)
    {
      cmp_result = compare_version_to_check(version:version, comparator:'>=', cmp_ver:constraint.min_branch);
      if (vcf::is_error(cmp_result)) return cmp_result;

      if (!cmp_result) return FALSE;
    }

    # Check that we don't exceed maximum version (if specified)
    if (constraint.max_branch)
      return compare_version_to_check(version:version, comparator:'<=', cmp_ver:constraint.max_branch);
    # If we've made it this far, all of the above constraints were met
      return TRUE;
  }

  ##
  # Do comparison and check if given condition is met.
  #
  # @param [version:string]    Version being checked (already parsed)
  # @param [comparator:string] Operator being used for comparison (<, <=, >, >=, =)
  # @param [cmp_ver:string]    Version being compared to
  #
  # @return [bool] True or False based on validity of logical statement
  #         [list] Error if one occurs
  #
  # @remark This is different form VCF as it loops based on the cmp_ver segment length. This will also check the
  # granulartity of the verison and error if it is not granular enough
  ##
  function compare_version_to_check(version, comparator, cmp_ver)
  {
    local_var comparison_result, i, seg, lengths_differ, pad_result, tmp_v, tmp_c, gran;

    if (empty_or_null(version)) return vcf::arg_error(arg:'version', func:FUNCTION_NAME);
    if (empty_or_null(comparator)) return vcf::arg_error(arg:'comparator', func:FUNCTION_NAME);
    if (empty_or_null(cmp_ver)) return vcf::arg_error(arg:'cmp_ver', func:FUNCTION_NAME);

    cmp_ver = vcf::parse_version(cmp_ver);
    if (vcf::is_error(cmp_ver)) return cmp_ver;

    # Compare version segments (release and pre-release segments)
    # in order.
    for (i=0; i<max_index(cmp_ver); i++)
    {
      for (seg=0; seg<max_index(cmp_ver[i]); seg++)
      {
        comparison_result = vcf::compare_version_segments(version[i][seg], cmp_ver[i][seg]);
        if (comparison_result != 0) break;
      }
      if (comparison_result != 0) break;
    }

    switch (comparator)
    {
      case '=':
        return comparison_result == 0;
      case '<':
        return comparison_result < 0;
      case '>':
        return comparison_result > 0;
      case '<=':
        return comparison_result <= 0;
      case '>=':
        return comparison_result >= 0;
      default:
        return new('vcf::Error', 'An invalid comparator \'' + comparator + '\' was passed to ' + FUNCTION_NAME + '.');
    }
  }

  ##################
  # Date Functions #
  ##################
  ##
  # Converts timestamp of YYYYMMDDHHmmSS to Unix timestamp.
  #
  # @param [time:string] Timestamp in the format of YYYYMMDDHHmmSS
  #
  # @return [string] Unix timestamp
  ##
  function to_epoch(time)
  {
    return mktime_tz(
        year : int(substr(time, 0, 3)),
        mon  : int(substr(time, 4, 5)),
        mday : int(substr(time, 6, 7)),
        hour : int(substr(time, 8, 9)),
        min  : int(substr(time, 10, 11)),
        sec  : int(substr(time, 12, 13)),
        tz   : 'GMT Standard Time'
      );
  }

  ##
  # Make a human readable time format of Month Day, Year, from the epoch timestamp.
  #
  # @param [date:string] Date in the format epoch format
  #
  # @return [string] Readable time format of Month Day, Year.
  ##
  function print_date(date)
  {
    local_var num_mon;

    num_mon = make_array(
        1,  'January',
        2,  'February',
        3,  'March',
        4,  'April',
        5,  'May',
        6,  'June',
        7,  'July',
        8,  'August',
        9,  'September',
        10, 'October',
        11, 'November',
        12, 'December'
    );

    date = localtime(date, utc:TRUE);

    return num_mon[date['mon']] + ' ' + date['mday'] + ', ' + date['year'];
  }

  ##
  # Converts the second difference of Unix timestamps to expected report format.
  # XX Years, XX Months, XX Days | XX Total Days
  #
  # @param [sec:int] The number of seconds to convert.
  #
  # @return [string] Time since in the standard report format
  ##
  function format_seconds_to_report(sec)
  {
    local_var years,months,weeks,t_days;

    t_days = ((sec/60)/60)/24;
    years = t_days/365;
    months = t_days/30;
    weeks = t_days/7;

    if (years >= 1)
    {
      if (years == 1)
        return '>= ' + years + ' year';
      else
        return '>= ' + years + ' years';
    }
    else if (months >= 6)
      return '>= 6 months';
    else if (months >= 1)
      return '>= 1 month';
    else if (weeks >= 1)
      return '>= 1 week';
    else
      return '< 1 week';
  }

  ##
  # Just acts as a wraper for testing.
  #
  # @return [int] The return of unixtime()
  ##
  function get_unixtime()
  {
    return int(gettimeofday());
  }
}
