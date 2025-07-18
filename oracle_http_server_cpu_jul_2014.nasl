#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76618);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/19");

  script_cve_id("CVE-2014-4222", "CVE-2014-4251");
  script_bugtraq_id(68650, 68652);

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (July 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is affected by multiple vulnerabilities in relation to
the Oracle WebLogic plugins.");
  # https://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77697fb1");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=1666884.1");
  # https://support.oracle.com/epmos/faces/ui/patch/PatchDetail.jspx?patchId=18423842
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3af02a2b");
  # https://support.oracle.com/epmos/faces/ui/patch/PatchDetail.jspx?patchId=18423831
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7166c521");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2014 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4251");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_rdbms_cpu_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var installs = get_kb_list_or_exit('Oracle/OHS/*/Version');
var mwinstalls = make_array();
var install, mwohome;
 
# For this check, we need Middleware home which should be
# oracle_common one directory up
foreach install (keys(installs))
{
  mwohome = install - 'Oracle/OHS/';
  mwohome = mwohome - '/Version';

  mwohome = ereg_replace(pattern:'^(/.*/).*$', string:mwohome, replace:"\1oracle_common");

  # Make sure the component that is being patched exists in
  # the Middleware home
  if (find_oracle_component_in_ohome(ohome:mwohome, compid:'oracle.wlsplugins'))
  {
    mwinstalls[mwohome] = installs[install];
  }
}

var patches = make_array();
patches['11.1.1.7'] = make_list('18423831', '19582372');
patches['12.1.2.0'] = make_list('18423842', '19485397','21768251','21773977');

if (max_index(keys(mwinstalls)) > 0) oracle_product_check_vuln(product:'Oracle HTTP Server', installs:mwinstalls, patches:patches, low_risk:TRUE);
exit(0, 'No Middleware Homes were found with the oracle.wlsplugins component.');
