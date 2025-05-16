#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211853);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/27");

  script_cve_id(
    "CVE-2024-36302",
    "CVE-2024-36303",
    "CVE-2024-36304",
    "CVE-2024-36305",
    "CVE-2024-36306",
    "CVE-2024-36307",
    "CVE-2024-37289"
  );

  script_name(english:"Trend Micro Apex One Multiple Vulnerabilities (KA-0016669)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex One
prior to SP1 (Server Build 12980 and Agent Build 12980). It is, therefore, affected by multiple vulnerabilities,
including the following:

  - An origin validation vulnerability in the Trend Micro Apex One security agent could allow a local 
    attacker to escalate privileges on affected installations. Please note: an attacker must first obtain 
    the ability to execute low-privileged code on the target system in order to exploit this vulnerability. 
    (CVE-2024-36302)

  - A Time-of-Check Time-Of-Use vulnerability in the Trend Micro Apex One and Apex One as a Service agent 
    could allow a local attacker to escalate privileges on affected installations. Please note: an attacker 
    must first obtain the ability to execute low-privileged code on the target system in order to exploit 
    this vulnerability. (CVE-2024-36304)

  - A security agent link following vulnerability in Trend Micro Apex One and Apex One as a Service could 
    allow a local attacker to disclose sensitive information about the agent on affected installations. 
    Please note: an attacker must first obtain the ability to execute low-privileged code on the target 
    system in order to exploit this vulnerability. (CVE-2024-36307)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/en-US/solution/KA-0016669");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apex One SP1 (b12980/12980) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:apex_one");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_apex_one_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Apex One");

  exit(0);
}

include('vcf.inc');

var app = 'Trend Micro Apex One';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

app_info.display_version = app_info.version;

var constraints = [{ 'fixed_version' : '14.0.0.12980' , 'fixed_display' : '14.0.0.12980 - Service Pack SP1 b12980'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
