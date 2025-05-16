#TRUSTED 716252609dce0d9889ed8d0f6e42c8f91c9b836f2278849b5e2e97bb0b6b829ef4c888719dfbaee1a2e644cabd3fe405c0b628efe8abce02cb2f55a067b78696a04e6a7cd102b99b30a0977272671dcc80c821f209384448aed8a0b6a518c573193a54953131b3136891abd9bf24c17ec326022a66acf286decd6c54beae6b940ea934f92de66bc82dc6ce26212206291ece9093e21f3cd3576a99c9665677ebc927aab6fb914225645665dcb3f6b1126dd8de7c1ed0dae1e2f4eab40399d8d5be1a21727ace4b79857ec723dbe77525fdb6b74c8133782f702bd106014f7cc9d8723783aff6799cfc12544640c889e5e498a4d38b44e2c41b618a4c37c2587a97b3dc697c014bd2ab29934504b18ff2a51d25cd0f1dc0d9f8975e193ef83e7bdcf7e88f1f940b21eee4ad7913895eae7f617062699d80ae24463b7e3bfd77a818a6ca4f3afed680ca2dc48de269f76ffe59d30920efd25ce8e2da72f4f536a23ba658c241358cef1709c5e8e2416c13ffea0fef0cd1268fb3ada1aee8a3d9c48dff2b7a2396bd0ae1d308e379cdb430dee3d15b84b9d54cf60c51678bd2c398c6e20c7969577e252b607741b417b803bc2809a108e91e7db88f731466642996fd34ec9712d6e57eff9222e548b38cebf40ecf822bdc152bf414c8f4d119dab808b9d1b5551b3bad5ae1aa341f42f80027cf244d4be7a040efe74d9cf7439863
#TRUST-RSA-SHA256 29d2c214357044c18b3647a3dcf3bb5b63ea2d2a7eebbd323fcec7be580d8169b72a4b8e405abdab9f7e40b84642808205026a80e9b375931abedeb2b7cc6544180b736031e6983e4321fa4324579ae98835ce2798da8d05593edb3b11206102625712b37b1a9e015651c77d56bf9e80f62537189b3f89c1e909f226b2a4c7eceff913fbb69f4808f23a23f8c0825c3cf618d0bf3f7f3f153670e9d4bab3d6042d14504ba6c9c937bb6b3f519201505c1b9b70dcd33641020421ec4a6428cfaad5f6f9a7bddad0a107ee37c6369a986c8cfc21d227fe0cada103e67e46b8ec407fccfa2465500ba2374cc69b137c36d6fce4ac988ebe50b1e8b084102f99161dba7d28279cb3f90519150d37ca8c44e2574662f9c4adaf615b0eed4060e9b6eada0ff8fc865c3c65bd2692fc17aa260a542dee01ce14279e6019a7900d0da3af28abfb0ee90ba7676b0f2ca6906aa18321ec05fc556040c92c2da8d7cabfa2c1f4e7fb1736336ffcca5754835a4c19c5989adb17d26a593bcd38a3e6b869c65d1ff2ca5b90ce42fea673234bdbfbea6b22778ac8ece8be5fd61ebabbe9ce43d1666caa606f4d4007bb8c0560097e9bc1ae58a46318f59579e8947b46aa3577cd2d6603f9c8bd459aed47ab9c982e31c593266c01caac1749f1b6a01a9c430ddcd4509394e612b0414554bbf0ffc90cedc3f78913917dd27edbd3d62cbc41aac2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183960);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2023-44187");
  script_xref(name:"JSA", value:"JSA73151");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73151)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73151
advisory.

  - An Exposure of Sensitive Information vulnerability in the ' (CVE-2023-44187)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73151");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-Evolved-file-copy-CLI-command-can-disclose-password-to-shell-users-CVE-2023-44187
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd921a34");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73151");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S7-EVO'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R1-EVO'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S5-EVO'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S4-EVO'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S4-EVO'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S2-EVO'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
