##
# (C) Tenable Network Security, Inc.
##
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_sap.inc
#
# Revision: 1.4

include('vcf.inc');
include('http.inc');
include('compat_shared.inc');
include('install_func.inc');

namespace vcf
{
  namespace sap_netweaver_as
  {

    function get_app_info(kernel)
    {
        local_var app, port, app_info;

        if (isnull(kernel))
            kernel = FALSE;

        app = 'SAP Netweaver Application Server (AS)';
        get_install_count(app_name:app, exit_if_zero:TRUE);

        port = get_http_port(default:443);

        app_info = get_single_install(app_name:app, exit_if_unknown_ver:FALSE, port:port);
        
        # by default, the AS version is returned. if kernel == TRUE, the netweaver kernel version is already there
        if (!kernel)
            app_info['version'] = get_kb_item_or_exit('www/netweaver/' + port + '/extra_version');

        # vcf::parse_version() won't parse versions like 740 correctly, so add a fake  .0 to the end of it and set a
        # display_version
        if ("." >!< app_info['version'])
        {
            app_info['display_version'] = app_info['version'];
            app_info['version'] = app_info['version'] + '.0';
        }
        app_info['parsed_version'] = vcf::parse_version(app_info['version']);
        app_info['webapp'] = TRUE;
        app_info['port'] = port;

        return app_info;
    }

    function check_version_and_report(app_info, severity, constraints, strict, flags, abap, kernel) 
    {        
        if (isnull(app_info)) 
            return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if (isnull(severity)) 
            return arg_error(arg:'severity', func:FUNCTION_NAME);
        if (isnull(constraints)) 
            return arg_error(arg:'constraints', func:FUNCTION_NAME);
        if (isnull(abap)) # abap = FALSE by default
            abap = FALSE;
        if (isnull(kernel)) # kernel = FALSE by default
            kernel = FALSE; 
        if (isnull(flags)) # empty flags by default
            flags = make_array();         

        if ( kernel || (app_info['ABAP Version'] && abap) ||
              (app_info['AS Java Version'] && !abap))
        {
            vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:severity, flags:flags);
        }
        else
        {
           vcf::audit(app_info);
        }
    }
    
  }

}
