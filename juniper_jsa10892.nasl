#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178666);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2018-0057");
  script_xref(name:"JSA", value:"JSA10892");

  script_name(english:"Juniper Junos OS Vulnerability (JSA10892)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA10892
advisory.

  - On MX Series and M120/M320 platforms configured in a Broadband Edge (BBE) environment, subscribers logging
    in with DHCP Option 50 to request a specific IP address will be assigned the requested IP address, even if
    there is a static MAC to IP address binding in the access profile. In the problem scenario, with a
    hardware-address and IP address configured under address-assignment pool, if a subscriber logging in with
    DHCP Option 50, the subscriber will not be assigned an available address from the matched pool, but will
    still get the requested IP address. A malicious DHCP subscriber may be able to utilize this vulnerability
    to create duplicate IP address assignments, leading to a denial of service for valid subscribers or
    unauthorized information disclosure via IP address assignment spoofing. Affected releases are Juniper
    Networks Junos OS: 15.1 versions prior to 15.1R7-S2, 15.1R8; 16.1 versions prior to 16.1R4-S12, 16.1R7-S2,
    16.1R8; 16.2 versions prior to 16.2R2-S7, 16.2R3; 17.1 versions prior to 17.1R2-S9, 17.1R3; 17.2 versions
    prior to 17.2R1-S7, 17.2R2-S6, 17.2R3; 17.3 versions prior to 17.3R2-S4, 17.3R3; 17.4 versions prior to
    17.4R2; 18.1 versions prior to 18.1R2-S3, 18.1R3. (CVE-2018-0057)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2018-10-Security-Bulletin-Junos-OS-authd-allows-assignment-of-IP-address-requested-by-DHCP-subscriber-logging-in-with-Option-50-Requested-IP-Address-CVE-2018-0057
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92bd5b47");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10892");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S2', 'fixed_display':'15.1R7-S2, 15.1R8'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R4-S12', 'fixed_display':'16.1R4-S12, 16.1R8'},
  {'min_ver':'16.1R7', 'fixed_ver':'16.1R7-S2'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S7', 'fixed_display':'16.2R2-S7, 16.2R3'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S9', 'fixed_display':'17.1R2-S9, 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R1-S7', 'fixed_display':'17.2R1-S7, 17.2R2-S6, 17.2R3'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S4', 'fixed_display':'17.3R2-S4, 17.3R3'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R2-S3', 'fixed_display':'18.1R2-S3, 18.1R3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
