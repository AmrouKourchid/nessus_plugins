#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100573);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/25");

  script_cve_id("CVE-2017-7849", "CVE-2017-7850");
  script_bugtraq_id(97951, 97952);

  script_name(english:"Tenable Nessus Agent 6.10.x < 6.10.5 Multiple Vulnerabilities (TNS-2017-10)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Nessus Agent installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Nessus Agent installed on the remote host is
6.10.x prior to 6.10.5. It is, therefore, affected by the following
vulnerabilities :

  - A denial of service vulnerability exists in the agent
    mode functionality due to insecure permissions. An
    authenticated, remote attacker can exploit this, via a
    specially crafted sequence of events, to prevent the
    agent from conducting scans. (CVE-2017-7849)

  - A local privilege escalation vulnerability exists in the
    agent mode functionality due to insecure permissions. A
    local attacker can exploit this, via a specially crafted
    sequence of events, to gain elevated privileges.
    (CVE-2017-7850)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent version 6.10.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin", "nessus_agent_installed_macos.nbin", "nessus_agent_installed_linux.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Tenable Nessus Agent");

constraints = [
  { "min_version" : "6.10", "fixed_version" : "6.10.5" },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
