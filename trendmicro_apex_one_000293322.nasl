#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190416);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id(
    "CVE-2023-34144",
    "CVE-2023-34145",
    "CVE-2023-34146",
    "CVE-2023-34147",
    "CVE-2023-34148"
  );

  script_name(english:"Trend Micro Apex One Multiple Vulnerabilities (000293322)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex One
prior to SP1 (Server Build 12033 and Agent Build 12033). It is, therefore, affected by multiple vulnerabilities:

  - Untrusted search path vulnerabilities in the Trend Micro Apex One and Apex One as a Service security agent could 
    allow a local attacker to escalate their privileges on affected installations. (CVE-2023-34144, CVE-2023-34145)

  - Exposed dangerous function vulnerabilities in the Trend Micro Apex One and Apex One as a Service security agent 
    could allow a local attacker to escalate privileges and write an arbitrary value to specific Trend Micro agent 
    subkeys on affected installations. (CVE-2023-34146, CVE-2023-34147, CVE_2023-34148)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/dcx/s/solution/000293322?language=en_US");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apex One SP1 (b12033/12033) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
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

var constraints = [{ 'fixed_version' : '14.0.0.12033' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
