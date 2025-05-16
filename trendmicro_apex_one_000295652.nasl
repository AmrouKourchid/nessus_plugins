#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190415);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id(
    "CVE-2023-47192",
    "CVE-2023-47193",
    "CVE-2023-47194",
    "CVE-2023-47195",
    "CVE-2023-47196",
    "CVE-2023-47197",
    "CVE-2023-47198",
    "CVE-2023-47199",
    "CVE-2023-47200",
    "CVE-2023-47201",
    "CVE-2023-47202"
  );

  script_name(english:"Trend Micro Apex One Multiple Vulnerabilities (000295652)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex One
prior to SP1 (Server Build 12526 and Agent Build 12526). It is, therefore, affected by multiple vulnerabilities:

  - An agent link vulnerability in the Trend Micro Apex One security agent could allow a local attacker to escalate 
    privileges on affected installations. (CVE-2023-47192)

  - Several origin validation vulnerabilities in the Trend Micro Apex One security agent could allow a local attacker 
    to escalate privileges on affected installations. (CVE-2023-47193, CVE-2023-47194, CVE-2023-47195, CVE-2023-47196,
    CVE-2023-47197, CVE-2023-47198, CVE-2023-47199)

  - Two plug-in manager origin validation vulnerabilities in the Trend Micro Apex One security agent could allow a 
    local attacker to escalate privileges on affected installations (CVE-2023-47200, CVE-2023-47201)

  - A local file inclusion vulnerability on the Trend Micro Apex One management server could allow a local attacker to 
    escalate privileges on affected installations. (CVE-2023-47202)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/dcx/s/solution/000295652?language=en_US");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apex One SP1 (b12526/12526) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47202");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:apex_one");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_installed.nasl", "trendmicro_apex_one_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Apex One");

  exit(0);
}

include('vcf.inc');

var app = 'Trend Micro Apex One';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

app_info.display_version = app_info.version;

var constraints = [{ 'fixed_version' : '14.0.0.12526' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
