#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211821);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2024-36359");

  script_name(english:"Trend Micro InterScan Web Security Virtual Appliance (IWSVA) XSS (KA-0016722)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by a cross-site scripting vulnerability");
  script_set_attribute(attribute:"description", value:
"A cross-site scripting (XSS) vulnerability in Trend Micro InterScan Web Security Virtual Appliance (IWSVA) 6.5 could 
allow an attacker to escalate privileges on affected installations. Please note: an attacker must first obtain the 
ability to execute low-privileged code on the target system in order to exploit this vulnerability.

Note that Nessus has not tested for this issue but has instead relied solely on the application's self-reported 
version number.");
  # https://success.trendmicro.com/en-US/solution/KA-0016722
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e04fc2ed");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the IWSVA version 6.5 SP3 Patch 2 (b3367) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36359");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:interscan_web_security_virtual_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_iwsva_version.nbin");
  script_require_keys("Host/TrendMicro/IWSVA/version", "Host/TrendMicro/IWSVA/build", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');

var version = get_kb_item_or_exit('Host/TrendMicro/IWSVA/version');
var build = get_kb_item_or_exit('Host/TrendMicro/IWSVA/build');

# Detection doesn't guarantee SP version - Vuln only affects SP2 so making paranoid 
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Detection may report the build as 'Unknown'
if (build == 'Unknown')
  exit(1, 'Unable to accurately determine the build number of the InterScan Web Security Virtual Appliance install');

var fixed_build = '3367';
if (!(version =~ '^6\\.5') || ver_compare(ver:build, fix:fixed_build, strict:FALSE) >= 0)
  audit(AUDIT_HOST_NOT, 'affected');

var report =
  '\n  Installed version : 6.5 Build ' + build +
  '\n  Fixed version     : 6.5 Build ' + fixed_build +
  '\n';

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
