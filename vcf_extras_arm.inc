##
# (C) Tenable, Inc.
##
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# vcf_extras_arm.inc
#
# Revision: 1.1

include('compat_shared.inc');
include('vcf.inc');

namespace vcf
{
  namespace arm
  {
    namespace mali_gpu
    {
      function custom_parse()
      {
        var check_string = _FCT_ANON_ARGS[0];
        var m = pregmatch(string:check_string, pattern:'r([0-9]+)p([0-9]+)');
        if (empty_or_null(m))
          return parse_error(str:check_string, index:0, msg:'Version not in expected form');
        return [[m[1], m[2]], [0]];
      }
      function get_app_info(app)
      {
        vcf::set_custom_parse_version(@custom_parse);
        return vcf::get_app_info(app:app);
      }
      function filter_constraints(app_info, constraints)
      {
         var result = make_list();
         foreach var constraint (constraints)
         {
           if (empty_or_null(app_info['GPU Family']) || app_info['GPU Family'] == 'unknown')
           {
              constraint.require_paranoia = TRUE;
              append_element(var:result, value:constraint);
           }
           else if (empty_or_null(constraint.family) || app_info['GPU Family'] == constraint.family)
           {
              append_element(var:result, value:constraint);
           }
         }
         return result;
      }
      # Added a 'family' entry to each constraint that will match against the family in the
      # app_info. If the family is unknown then the check will default to require_paranoia
      # behaviour
      function check_version_and_report(app_info, constraints, severity, flags, require_paranoia)
      {
        constraints = filter_constraints(app_info:app_info, constraints:constraints);
        if (empty_or_null(constraints))
          vcf::audit(app_info);
        vcf::check_version_and_report(
          app_info:app_info,
          constraints:constraints,
          severity:severity,
          flags:flags,
          require_paranoia:require_paranoia);
      }
    }
  }
}
