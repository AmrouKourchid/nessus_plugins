#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024-11-26.
# This plugin has been deprecated. Replaced by oracle_siebel_cpu_apr_2014.nasl (212371).
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74467);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2014-2468");
  script_bugtraq_id(66848);

  script_name(english:"Oracle Siebel UI Framework CVE-2014-2468 Remote Security Vulnerability (April 2014 CPU) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated. Replaced by oracle_siebel_cpu_apr_2014.nasl (212371).");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. Replaced by oracle_siebel_cpu_apr_2014.nasl (212371).");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:siebel_crm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");
  script_require_keys("Oracle/siebel_server/Installed");

  exit(0);
}

exit(0, "This plugin has been deprecated. Replaced by oracle_siebel_cpu_apr_2014.nasl (212371).");
