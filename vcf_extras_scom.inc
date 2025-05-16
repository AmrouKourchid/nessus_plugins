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
# vcf_extras_scom.inc
#
# Revision: 1.1

include('compat_shared.inc');
include('vcf.inc');

namespace vcf
{
  namespace scom
  {
    ##
    # Extends vcf::get_app_info for Microsoft System Center Operations Manager (SCOM)
    # This function branches.
    #
    # @return an array containing application info
    ##
    function get_app_info()
    {
      # 2019:    "installed_sw/System Center Operations Manager Server"
      # 2016:    "installed_sw/System Center Operations Manager 2016 Server"
      # 2012 R2: "installed_sw/System Center Operations Manager 2012 Server"
      var scom_kbs = get_kb_list('installed_sw/System Center Operations Manager *Server');

      if ( empty_or_null(scom_kbs) )
        ::audit(AUDIT_NOT_INST, "System Center Operations Manager Server");

      var scom_kb = branch(keys(scom_kbs));
      var app_name = scom_kb - 'installed_sw/';
      return vcf::get_app_info(app:app_name, win_local:TRUE);
    }
  }
}