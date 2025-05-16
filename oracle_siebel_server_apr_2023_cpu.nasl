#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024-11-26.
# This plugin has been deprecated. Replaced by oracle_siebel_cpu_apr_2023.nasl (212431).
##

include('compat.inc');

if (description)
{
  script_id(185085);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2023-21909");

  script_name(english:"Oracle Siebel < 23.4 (April 2023 CPU) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated. Replaced by oracle_siebel_cpu_apr_2023.nasl (212431).");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. Replaced by oracle_siebel_cpu_apr_2023.nasl (212431).");
  # https://www.oracle.com/security-alerts/cpuapr2023.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2aefbee2");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21909");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:siebel_crm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 Tenable Network Security, Inc.");
  script_require_keys("Oracle/siebel_server/Installed", "installed_sw/Oracle Siebel Server");

  exit(0);
}

exit(0, "This plugin has been deprecated. Replaced by oracle_siebel_cpu_apr_2023.nasl (212431).");
