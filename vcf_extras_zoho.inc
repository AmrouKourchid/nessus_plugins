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
# vcf_extras_zoho.inc
#
# Revision: 1.7

include('compat_shared.inc');
include('install_func.inc');
include('vcf.inc');
include('http.inc');

namespace vcf
{
  namespace zoho
  {
    namespace servicedesk
    {
      // Change the 11.3 Build 11302 format into 11.3.11302
      // app variable to select either MSP or non-MSP version.
      function get_app_info(app, port) {
        var install, build, parsed_version;

        install = get_single_install(app_name:'manageengine_servicedesk', port:port, exit_if_unknown_ver:TRUE);
        install.app = install.Product;
        install.port = port;
        install.webapp = TRUE;
        install.display_version = install.version;
        if (!isnull(app) && app != install.Product)
          vcf::audit(install);

        build = pregmatch(string:install.version, pattern:"^([0-9\.]+) Build ([0-9]+)");
        if(empty_or_null(build)) ::audit(AUDIT_VER_NOT_GRANULAR, app, install.version);
        install.version = build[1] + '.' + build[2];
        parsed_version = vcf::parse_version(install.version);
        if (vcf::is_error(parsed_version)) return vcf::vcf_exit(1, parsed_version.message);
        install.parsed_version = parsed_version;
        return install;
      }
    }
    namespace desktop_central
    {
      function get_app_info() {
        var app_info, parsed_version, port, url;

        port = get_http_port(default:8020);
        app_info = vcf::get_app_info(app:'ManageEngine Desktop Central', port:port, webapp:TRUE);

        if (app_info.MSP)
          app_info.app = app_info.app + ' MSP';

        if (app_info.build == UNKNOWN_VER || empty_or_null(app_info.build))
        {
          url =  build_url(port:port, qs:app_info.path);
          exit(0, 'The build number of '+ app_info.app +' version ' + app_info.version + ' listening at ' + url + ' could not be determined.');
        }

        # Set app_info.version to app_info.build, needed for ver compare, and set a display-version
        app_info.display_version = app_info.version + ' build ' + app_info.build;
        app_info.version = app_info.build;

        # workaround for the issue with single segment versions
        parsed_version = vcf::parse_version(app_info.version + '.0');
        if (vcf::is_error(parsed_version))
          return vcf::vcf_exit(1, parsed_version.message);
        app_info.parsed_version = parsed_version;

        return app_info;
      }
    }
    namespace fix_parse
    {
      function get_app_info(app, port, webapp) {
        var app_info, parsed_version;

        if (empty_or_null(webapp))
          webapp = TRUE;

        app_info = vcf::get_app_info(app:app, port:port, webapp:webapp);

        # workaround for the issue with single segment versions
        parsed_version = vcf::parse_version(app_info.version + '.0');
        if (vcf::is_error(parsed_version))
          return vcf::vcf_exit(1, parsed_version.message);
        app_info.parsed_version = parsed_version;

        return app_info;
      }
    }
    namespace combined_fix_parse
    {
      function get_app_info(app) {
        var app_info, parsed_version;

        app_info = vcf::combined_get_app_info(app:app);

        # workaround for the issue with single segment versions
        parsed_version = vcf::parse_version(app_info.version + '.0');
        if (vcf::is_error(parsed_version))
          return vcf::vcf_exit(1, parsed_version.message);
        app_info.parsed_version = parsed_version;

        return app_info;
      }
    }
    namespace adaudit
    {
      function get_app_info()
      {
        # Local and remote detections register different app names
        # and place the build number in different locations
        var app_name = 'Zoho ManageEngine ADAudit Plus';
        var local_installs = get_combined_installs(app_name:'Zoho ManageEngine ADAudit Plus');
        var remote_installs = get_combined_installs(app_name:'ManageEngine ADAudit Plus');
        var installs = [];
        var install;

        if (local_installs[0] == IF_OK)
        {
          foreach install (local_installs[1])
          {
            install.app = app_name;
            if (!empty_or_null(install.Build) && install.version != UNKNOWN_VER)
            {
              install.display_version = install.version + ', Build ' + install.Build;
              install.parsed_version = vcf::parse_version(install.Build + '.0');
            }
            else
            {
              install.version = UNKNOWN_VER;
            }
            append_element(var:installs, value:install);
          }
        }
        if (remote_installs[0] == IF_OK)
        {
          foreach install (remote_installs[1])
          {
            install.app = app_name;
            install.webapp = TRUE;
            if (install.version != UNKNOWN_VER)
              install.parsed_version = vcf::parse_version(install.version + '.0');
            append_element(var:installs, value:install);
          }
        }

        if (empty_or_null(installs))
          ::audit(AUDIT_NOT_INST, "Zoho ManageEngine ADAudit Plus");

        install = branch(installs);
        if (install.version == UNKNOWN_VER)
        {
          if (install.webapp)
          {
            if (!empty_or_null(install['path']))
              ::audit(AUDIT_UNKNOWN_WEB_APP_VER, install.app, build_url2(qs:install['path'], port:install.port));
            else
              ::audit(AUDIT_UNKNOWN_WEB_SERVER_VER, install.app, install.port);
          }
          else
            ::audit(AUDIT_UNKNOWN_APP_VER, install.app);
        }
        return install;
      }
    }
  }
}
