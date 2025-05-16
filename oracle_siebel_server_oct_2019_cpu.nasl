#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024-11-26.
# This plugin has been deprecated. Replaced by oracle_siebel_cpu_oct_2019_19_8.nasl (212396).
##

include('compat.inc');

if (description)
{
  script_id(185087);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2019-2965");

  script_name(english:"Oracle Siebel < 19.9 (October 2019 CPU) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated. Replaced by oracle_siebel_cpu_oct_2019_19_8.nasl (212396).");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. Replaced by oracle_siebel_cpu_oct_2019_19_8.nasl (212396).");
  # https://www.oracle.com/security-alerts/cpuoct2019.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c94f8e4");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
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

exit(0, "This plugin has been deprecated. Replaced by oracle_siebel_cpu_oct_2019_19_8.nasl (212396).");
