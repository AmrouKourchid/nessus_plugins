#TRUSTED a83bbc12fba3722e914ad97d04e29e2ca805dace0b2eb2e45efb3a77d615c42e06ac6f87ee26396710729acde21b079d4143822b25f5e6c1a949dd12e7666f5a8676d12706ec2e924e46e52604fde23ff5b70ffd8cce48e0156c2148980755e79776b69cf17dc3710c377b769c05c178e460adf2c63e01026a5aae16fb28d16a898fc7f47e6169fa3aa3c1a6abcf4d85d16f1297474176b5a2427c4f93b6b69a8bb60e0f0bae97e02ae8d995996b99da6d2fb2c83c5c6636048e217207eaba9030c531fab02e090488cd7f24c8ba2bf8a18c8091e8f066d499e23fdc2eb024e2a0b82428dca9539f87539337c75b64cda62d49953c5671f4df5cd5e90412acb7fd1d11e7f71b5eaf0d9ee911866136850d75898dd1476ceb95e03bc0b33b85fcc0e50678358d9673c14d6e2003f26ab2c41673101cab2555320d0d9d1ac6184b016ff1162661bc985136a59c308cea8f6af5d6f14fb6dde4250bad8ce1dda07f93354656215088e81b085370d3d83a25bd4dde4e8eb7e59e18aad18a86b9e4f2080157a46039cc3f01a9ac7c8016d45cf544b4202446bc3385ab251ef679946095e132f7e2cf2546416c5bb91259cef51668d275d7715edf2e72faf11dffd97b46f0a29b7b9f2a6df313df360c8efae33e4f86eca693c600b0dda9cf26ebd7d3869c39a7c9cd6467f19d9a0c127b8dfc4ba9040146d1ca6334191561fcf37a52
#TRUST-RSA-SHA256 5f3c1022723abd92daf3db9da316178e323635ce6532308307ac3d09921e692973372562f2928e6dd75645822fcd2a910ec8715a46f24499d9812327bb5504c3467d55b87a4ef7ccbaded3785b2c100ad94416dd90976333f012d84773d8f2c3f27abb42426e572111b81527ccef8b393126148d5aae7263c3dde87bd9dce2b0dcbd2f84f58efc48da07335a33286f0bf47e8be9149af8cad4571e18e02d9794676a6d37b3c1b2e6bb3be3503520e691a18d503e6c8171f40492495c5d8eee61a146f7ee1e096665a28a5e062ea440de708755ea517139f8a8d17885dbdc4f81b933514195eed506c934e253209bff445715bcdb33b9c143ed6c176a2ca218bc7918b32006edb1b9f8f446a1445b4d66b201eec03cd4fe764cc650be514807aed030ea16337278314223c5f2a6514d52f18d73b1677bb06077c33de19529c060a8213203e0153d9e55f035171cad6c59c47fd958df720a056f10e3f03a94de048e6945e8238300df0680d096492b462014b03ae889101f8d3974258a3943d7c29e4db5459afdd93b7823436e189fb36de39f66cb2e3aa74710f883bf1ee971b324fe1df111e4b5446d3a9017639d0be51910f7d9140a8167fbedb1ede8169afdfbae4c0a5f052554b9fd3130aa77b032969a44c478d2bd1853a344f4f03deb3844531cc6551ca5bfc509f6589651abd21fe9c0ea7158d98170e1e49c4830e175
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133051);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/29");

  script_cve_id("CVE-2020-1607");
  script_xref(name:"JSA", value:"JSA10986");
  script_xref(name:"IAVA", value:"2020-A-0012-S");

  script_name(english:"Junos OS: Cross-Site Scripting (XSS) in J-Web (JSA10986)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a cross-site scripting
(XSS) vulnerability in J-Web due to insufficient XSS protection. An unauthenticated, remote attacker can exploit this,
via injecting web script or HTML to hijack the target user's J-Web session and perform administrative actions on the on
the Junos device as the targeted user. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10986
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15e6942c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in Juniper advisory JSA10986.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1607");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.3'] = '12.3R12-S15';
if (model =~ '^SRX') {
  fixes['12.3X48'] = '12.3X48-D86';
}
if (model =~ '^EX' || model =~ '^QFX') {
  fixes['14.1X53'] = '14.1X53-D51';
}
fixes['15.1F'] = '15.1F6-S13';
fixes['15.1'] = '15.1R7-S5';
if (model =~ '^SRX') {
  fixes['15.1X49'] = '15.1X49-D181';
}
if (model =~ '^QFX5200' || model =~ '^QFX5110') {
  fixes['15.1X53'] = '15.1X53-D238';
}
if (model =~ '^EX2300' || model =~ '^EX3400') {
  fixes['15.1X53'] = '15.1X53-D592';
}
fixes['16.1'] = '16.1R4-S13';
fixes['16.2'] = '16.2R2-S10';
fixes['17.1'] = '17.1R2-S11';
fixes['17.2'] = '17.2R1-S9';
fixes['17.3'] = '17.3R2-S5';
fixes['17.4'] = '17.4R2-S6';
fixes['18.1'] = '18.1R3-S7';
fixes['18.2'] = '18.2R2-S5';
fixes['18.3'] = '18.3R1-S6';
fixes['18.4'] = '18.4R1-S5';
fixes['19.1'] = '19.1R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If J-Web is not enabled, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set system services web-management http(s)?";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}
junos_report(model:model, ver:ver, fix:fix, override:override, severity:SECURITY_WARNING, xss:TRUE);
