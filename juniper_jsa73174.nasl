#TRUSTED a8c497441df3a858de1c160b3cbf9b1989638fa3156ce2cb1cd1e0d64c6774ea2d7a7371247b61cb332a0f854e06f7ddc3d97a5744b65450fce5a06a9823d8b482cca44aa3de47b6cc7450067aa0db7d0c1ee9328aa22e4bc0b2b94bddfcc304e94662250c53b42538427afa6450803a229ea4461bd98ea2c060afdf9b94f3060b71ca4d216d6f9a33f9b8beebf660a02906c80a177cf436f98fbc6342a28dbb4506abfa32a1fb7784b31330d4d552b25c19d462c697a2b40d475316bc5c579a2a233e64a7f4c4d3bdb266414b1e81d3871084f72fd20a5a93640335f1e4eb1e469d95faaae4bea1311dab27115f92d91c6d055361481b7befc9d82198cf47243e9739d2a37dcb269d0e590123010fb021197dfafbb9941732137ae16d314b4dd41be8a894dd323b7d177e0964e8bae1c6242d52e3b7ab0cfad1a44097f89f7c3d08d5af3d2b53fd7298d38ee947deaaff3bc48eeea4ec5effd67c5559aec06e95c60e608c01762d7fbeb3596d6e14b11796e857d5cf7dab7a76e943d0243fd1ec7f16fbba420b652e33ad5866bfac424f80991a93682f6a50532da005880538082a108430b953349f0d8e4d71710bcaca00df1722dd217a954f49c57069551a8c8deb251e9a396c7c946baa8259aa7c0a49aeb60309ea1af0c3a5443ffc40a5bcdd6fcb5f7a029e08a264849269c70b6b08e5e12fb76d8fdf11f18366ab1f07
#TRUST-RSA-SHA256 4d5466affd9ad487a22a3766ce5efff6652a7971db41a5e4e2adffd50148715a9be2f87b37f96d0bb4c2a2b9427c1852565e55c11741e681a589bb69b915e9d553ce19bd3454024b76ab6acce2f32327be399abf87baf7fdfefef0ae2de92351c3b7b6285b26ffeb82dc7266eac4fb3b33e289064417500a5e630817d99b1f2d8226b677f9a02f887f54ee360ade7961784eee73479fe65a2d279d24c38a6a840c4bc1c65c9d736c1f1b6c08188265af096488304246a5baa8334ddfb8ef585196cda26cf28bac0206c6861b430ead3d2ee183412a1b70c97563697bf9795f055835bccf05fa7e1a01fc387ad5f8d0d548b9054a87299400a8775d7e937f7d914706ad433b289fe26cdecef0ba599e18345d273e311f0329f3a5bdb9b882b36006efeea238e3a21f41591a925643ac32b5120e5152c188131c7cba9e3b500334acfbb6a8736b6802b4842f2c3e12f3dbf5d4111b41b350769d85b6705b4e64fc40153f6125507b11238438270e99d3d0b10c9903dfb5a204940901d018d2d197606adc4f56e59b154930cef3075b1f1facf4e8fa517172ea536208534da5330debd186ad1939d5779e8e14f30631bba1d040869670b06952ddf21b3f3c5b1f6127f2eec7b584c9f2d1d88b49984197c8571202c0c6fb760eccffe67b4436eb72f753e638821428bdace2eeeaa7e1bcd515827de250e0d21db865b4e3ab482d03
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183875);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/25");

  script_cve_id("CVE-2023-36843");
  script_xref(name:"IAVA", value:"2023-A-0565");
  script_xref(name:"JSA", value:"JSA73174");

  script_name(english:"Juniper Junos OS DoS Vulnerability (JSA73174)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73174
advisory.

  - An Improper Handling of Inconsistent Special Elements vulnerability in the Junos Services Framework (jsf)
    module of Juniper Networks Junos OS allows an unauthenticated network based attacker to cause a crash in
    the Packet Forwarding Engine (pfe) and thereby resulting in a Denial of Service (DoS). 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73174");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-SRX-Series-The-PFE-will-crash-on-receiving-malformed-SSL-traffic-when-ATP-is-enabled-CVE-2023-36843
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67f2470a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73174");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S8', 'fixed_display':'20.4R3-S8, 20.4R3-S9'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S6'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'fixed_display':'22.3R2-S2, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1', 'fixed_display':'22.4R2-S1, 22.4R3'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set services security-metadata-streaming-policy", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
