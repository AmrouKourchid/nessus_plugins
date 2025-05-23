#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150416);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/27");

  script_cve_id("CVE-2020-1971", "CVE-2020-13871");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"IAVA", value:"2021-A-0038-S");

  script_name(english:"Oracle MySQL Workbench < 8.0.23 Multiple Vulnerabilities (Jan 2021)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL Workbench installed on the remote Windows host is prior to 8.0.23. It is, therefore, 
affected by multiple vulnerabilities as referenced in the advisory.

    - SQLite 3.32.2 has a use-after-free in resetAccumulator in select.c because the parse tree rewrite for window
    functions is too late. (CVE-2020-13871)

    - The X.509 GeneralName type is a generic type for representing different types of names. One of those name types
    is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a
    GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an
    EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack.
    (CVE-2020-1971)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f5cff95");
  script_set_attribute(attribute:"see_also", value:"https://www.mysql.com/products/workbench/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle MySQL Workbench version 8.0.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_workbench");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql_workbench");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_workbench_win_installed.nbin");
  script_require_keys("installed_sw/MySQL Workbench");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MySQL Workbench');

var constraints = [
  { 'fixed_version' : '8.0.23' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
