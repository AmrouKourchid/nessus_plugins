#TRUSTED 5e6e94b9ca1f51eead18729d9458b9048101c7707555c9d54975febfd2ac4befebd9a432d896b73b75e1b8f3d9aa641d397673b795d89a4b1824dead7a6777b63a3d9dc2d2d732eae919b5837f5c886cda9729489c9225b188bbb6d4ec0c4b6e4bb5a2297a7aeeab2f031f9c3fa5adb33180630e1481b6722387218b391110f8c22e8c6152e69f3eefab8495c02f72bdc198d60bc5a355b1235c17cf5b3bc7fc1e2487faea3969f22091e77376831cead4940c44f2e2508bb7f074e25526819122cae91c809babf76d72fca5ffcf7751c56c3bd33b5ee4519d5f40d7c2ee8f6087ff3b670242d33fe8b0361a302cd763b193f2fcd1b720d0aa43626d501fa965f4c03ae223b3ab74d23f9e263f5a06cd4f0763d5f0d906b70a1e8043dca89b1a2ddd31c4cf58fe9648b3669efddb782874f1e2f75bf54faa209fc943945b5970b0f2cbe9b8a0be1515b064e4b928a8343bd8c29b6f344ba55700a372211e0818406e366906a8c608be9c6758c92782a4dca0aff1eace9cb933cdc33c8d53e6f6083625bc67d367860a12c1d2fbe161fa5cd8d2ff02841004183b2f59f13e673ad836b3ea542c378c9dee9b2ffc30ddbfda6cdc07ec88e8c65a24580af47eefc948e8368c8f41394d80a035c0ff1d3c214cdb0bfbd39e9dd03ce1a42e46a07650b9fae4c64a37ea0c1ddf666f6b44ec5003d9ce16d116bfa27c106f2bc1547456
#TRUST-RSA-SHA256 73cf56a9aafff3e92c8caeddd709023ff8cfeeee155e69bd6a07568ad17c73e2dbf6835b07603998fada3349e1deee8fa4b0b45987b3c9cf70ee830848a4cca07d767b49a8ab022d4e11913097f790a164f0d524b642b02d86fe6b4ebbe5dd3822b73b804e052b5f1982ac0702f866bfedaa1ccab2aae900445ecd93e0f87196c0edce4050c721fdf394f87f88ddb689f46416362d7e2d32c9bd7badde1221a06823ac591a8661f47c9cb02efd509837cb5e08b00bd77a918e69d4e9519f72e353db89b4a998fa2b792fbcd41580ac3d662c0e4350070862bb0577f9e212de5964ef8f1767b156301de3cffc060b007d125ebb0b3d402ea129694f197631a42c18f10be4eb00d5349250cbb782f734274e2486e9532850c0909558209bd987c3d3ae906d9213bae53c0006f079d9436a3121ab030fbe0223c3f733a6d24074b56d7dad43ad10beac7a6e465c68ea2d4ab9dc957ae4933d8eb8d1f1c41f237db5907ebdac41ba64fbfba548b9336cafd5bdcaf934d267b0c3c8bce2ea58ce866ff2009333c3e286e4760f527fa78a0bc9a4e4a3c4e023bcb905f664f0ab853a8d910a474ac312a78a70ea60a2e69f1d195cb03a8a54d198087d084ca7d6c8277fe4d338dbf30cd78e694e050c7c8507fa9f0cbed2612ee79d5093b203ca6da87a6dfecfdedc738b223c1f7c7d92f3cbbd1911d860a712477a95c05371ae260a65
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164339);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2022-22213");
  script_xref(name:"JSA", value:"JSA69717");
  script_xref(name:"IAVA", value:"2022-A-0280-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69717)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69717
advisory.

  - A vulnerability in Handling of Undefined Values in the routing protocol daemon (RPD) process of Juniper
    Networks Junos OS and Junos OS Evolved may allow an unauthenticated network-based attacker to crash the
    RPD process by sending a specific BGP update while the system is under heavy load, leading to a Denial of
    Service (DoS). Continued receipt and processing of this packet will create a sustained Denial of Service
    (DoS) condition. Malicious exploitation of this issue requires a very specific combination of load,
    timing, and configuration of the vulnerable system which is beyond the direct control of the attacker.
    Internal reproduction has only been possible through artificially created load and specially instrumented
    source code. Systems are only vulnerable to this issue if BGP multipath is enabled. Routers not configured
    for BGP multipath are not vulnerable to this issue. This issue affects: Juniper Networks Junos OS: 21.1
    versions prior to 21.1R3-S1; 21.2 versions prior to 21.2R2-S2, 21.2R3; 21.3 versions prior to 21.3R2,
    21.3R3; 21.4 versions prior to 21.4R1-S1, 21.4R2. Juniper Networks Junos OS Evolved: 21.1 versions prior
    to 21.1R3-S1-EVO; 21.2 version 21.2R1-EVO and later versions; 21.3 versions prior to 21.3R3-EVO; 21.4
    versions prior to 21.4R1-S1-EVO, 21.4R2-EVO. This issue does not affect: Juniper Networks Junos OS
    versions prior to 21.1. Juniper Networks Junos OS Evolved versions prior to 21.1-EVO. (CVE-2022-22213)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Denial-of-Service-DoS-vulnerability-in-RPD-upon-receipt-of-specific-BGP-update-CVE-2022-22213
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eee78d4c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69717");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (ver =~ 'EVO')
{
  var vuln_ranges = [
    {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1-EVO'},
    {'min_ver':'21.2', 'fixed_ver':'21.2R1-EVO'},
    {'min_ver':'21.3', 'fixed_ver':'21.3R3-EVO'},
    {'min_ver':'21.4', 'fixed_ver':'21.4R1-S1-EVO', 'fixed_display':'21.4R1-S1-EVO, 21.4R2-EVO'}
  ];
}
else
{
  var vuln_ranges = [
    {'min_ver':'21.1', 'fixed_ver':'21.1R3-S1'},
    {'min_ver':'21.2', 'fixed_ver':'21.2R2-S2', 'fixed_display':'21.2R2-S2, 21.2R3'},
    {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'fixed_display':'21.3R2, 21.3R3'},
    {'min_ver':'21.4', 'fixed_ver':'21.4R1-S1', 'fixed_display':'21.4R1-S1, 21.4R2'}
  ];
}

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set protocols bgp.*multipath"))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
