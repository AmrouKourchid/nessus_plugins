###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_oracle_em_ops_center.inc
#
# Revision: 1.3
###

include('compat_shared.inc');
include('vcf.inc');

namespace vcf
{
  namespace oracle_em_ops_center
  {
    ##
    # Builds app_info for Oracle Enterprise Manager Ops Center
    #
    # @return [array] an array containing application info
    ##

    function get_app_info()
    {
      var app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Ops Center');
      return app_info;
    }

    ##
    # Calls both vcf::check_version() and report_results()
    #
    # @param [app_info:array]   array containing application info. requires, at minimum, a
    #                           key/value pair for 'version'
    # @param [constraints:list] list of constraint arrays
    #                           constraints have a 'uce_patch', 'ui_patch' or '*_patch' where * is a
    #                           third party patch that Oracle has issued - e.g. for python
    # @param [severity:int]     severity used in reporting
    # @param [strict:boolean]   bool that determines whether or not version/fix should
    #                           require the same number of fields
    # @param [flags:array]      array of reporting flags (xss, sqli, xsrf)
    #
    # @remark
    # This function exits.
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      if(isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if(isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if(isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      var matching_constraint = vcf::check_version(version:app_info.parsed_version,
                                                   constraints:constraints,
                                                   strict:strict);
      if(vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      if(!isnull(matching_constraint))
      {
        var fix_patches = [];
        var installed_patches = [];
        var patches_specified = FALSE;
        var k, m, latest, all;
        foreach k (keys(matching_constraint))
        {
          m = pregmatch(pattern:'^(.*)_patch$', string:k);
          if(empty_or_null(m))
            continue;
          patches_specified = TRUE;
          if(m[1] == 'uce')
          {
            latest = app_info['UCE latest patch'];
            all = app_info['UCE patches'];
          }
          else if(m[1] == 'ui')
          {
            latest = app_info['UI or Other latest patch'];
            all = app_info['UI or Other patches'];
          }
          else
          {
            latest = app_info[m[1] + ' latest patch'];
            all = app_info[m[1] + ' patches'];
          }
          if(empty_or_null(latest) || int(latest) < int(matching_constraint[k]))
          {
            append_element(var:fix_patches, value:matching_constraint[k]);
          }
          if(!empty_or_null(all))
            installed_patches = make_list(installed_patches, split(all, sep:';', keep:FALSE));
        }

        if(patches_specified && empty_or_null(fix_patches))
          vcf::audit(app_info);

        var fix_patch;
        if(!empty_or_null(matching_constraint.fixed_display))
          fix_patch = matching_constraint.fixed_display;
        else
          fix_patch = join(sort(fix_patches));

        if(empty_or_null(fix_patches))
          vcf::vcf_exit(1, 'No fixed patch specified in constraint');

        report_results(
            app_info:app_info,
            patch:fix_patch,
            current_patches:join(sort(list_uniq(installed_patches))),
            severity:severity,
            flags:flags
        );
      }
      else return vcf::audit(app_info);

      return vcf::vcf_exit(0);

    }

    ##
    # Call security_report_v4() with given severity and flags
    #
    # @param [app_info:array]         app info to use in report
    # @param [patch:string]           the patch to include in report
    # @param [current_patches:string] patches currently applied
    # @param [severity:int]           SECURITY_(NOTE|HOLE|WARNING)
    # @param [flags:array]            xss, xsrf, and sqli
    #
    ##
    function report_results(app_info, current_patches, patch, severity, flags)
    {
      var report, report_items, order, port;
      var version_full, patch_version;

      report_items = make_array(
        'Path', app_info.path,
        'Version', app_info.version,
        'Fix Patch', patch
      );
      order = make_list('Path', 'Version');

      version_full = app_info['Full Patch Version'];
      if(!isnull(version_full)) {
        report_items['Ops Agent Version'] = version_full;
        append_element(var:order, value:'Ops Agent Version');
      }

      if(!empty_or_null(current_patches)) {
        report_items['Applied Patches'] = current_patches;
        append_element(var:order, value:'Applied Patches');
      }

      append_element(var:order, value:'Fix Patch');
      report = report_items_str(report_items:report_items, ordered_fields:order);
      port = app_info.port;
      if(isnull(port)) port = 0;
      store_structured_data(app_info:app_info, fix:patch, port:port);
      security_report_v4(severity:severity,
                         port:port,
                         extra:report,
                         xss:flags.xss,
                         xsrf:flags.xsrf,
                         sqli:flags.sqli,
                         proto:app_info.proto);

    }
  }
}
