###
# Microsoft version checks
###
include('vcf.inc');

namespace vcf
{
  namespace draytek
  {
    namespace vigor
    {
      ##
      # Overloads the vcf::check_version_and_report to correct the webapp assumption is there is a service
      #
      # @param [app:string] Name of the application
      ##
      function combined_get_app_info(app)
      {
        local_var install;

        if (isnull(app)) return arg_error(arg:"app", func:FUNCTION_NAME);

        install = vcf::combined_get_app_info(app:app);

        if (install.service)
          install.webapp = FALSE;

        return install;
      }
      ##
      # Overloads the vcf::check_version_and_report to also check for models
      #
      # @param [app_info:array] Applicaiton information structure object
      # @param [constraints:list] List of the constraint arrays that define vulnerable versions.
      # @param [models:list|NULL] List of affected models
      # @param [severity:int] Reporting severity level
      # @param [flags:array|NULL] Flags for identifying certain classes of vulnerabilities (XSS, XSRF, SQLi)
      ##
      function check_version_and_report(app_info, constraints, models, severity, flags)
      {
        local_var model, flag;
        flag = false;

        if (!isnull(models))
        {
           foreach model (models)
           {
              if (app_info['model'] >< model)
                flag = TRUE;
           }
        }

        if (!flag)
          exit(0, 'The ' +app_info.app+ ' with a model of ' +app_info.model+ ' is not affected.');

        vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:severity, flags:flags);
      }
    }
  }
}
