#TRUSTED adb14fdf40a12ff1197575c3a8e27e1ba2566ac90bdd84cdecfd6f1f9fe289c0c52a0cf4ec1f987de4319dfe3e3c84d31631f0684e368aa1506b9ebcc5c713735c3761dd9c5442278486aba39bd1e3ce4a332b65416bfd4b53a5294f4db06a3d3b6c4bb287f1cfbb9f4f4c042ed7c118070a7b11484c044a985c3cb9f07418c8b12c7c0037c0fa01aa9d0873277c2be3fdc4ec5c4a5ebe7118e01e9124d0f495131084b884272541cdb3d99e64cf3e36cf75f2a0d40c109ae19d6f94b0352e72408666d61797ce1d91926440d81386eb4a0659fa8eb9a47db795a1e34afe06c38ed45b71d428e79ba79675f91338b90c784f32a92065e115c64828da6f7705875eb391c3f1dc692109ec696508363af73c1d5594af98f1c7fb344aa8ac6293206b57ccbe381f5072df413459cf4e483964a0becdd489a8e86bc5df15368c705de0cd93c3d2a1bec236aecbadd224d06e2d728537af9110954bb7b27dae92ef61612cab30093707355be1c0aac79a616e3a106c1ab27f7a266be6e01fe03c10569ee2348c04dced5b4541ea6f2f03b943b1674a0007f7a94144cf4ec664fcd37a33aaee9270c294ad17087dfb9d0bca593a24fb5c0d29700d7c20d4da8c65279bf93053d83ebbb8b8498fe6602ecd24124e022b66f3e57da517d4c0a872e06d5d6bfb7058d0337977b5dbe71a9658b43cb6a63d5c5d95afe7d6f2c99e90d77054
#TRUST-RSA-SHA256 55885bf6187d66fff3dce93018b203391de86f34b0be0a4c3753c6a3b5fec8ffac57ede77adacd3219981be175008cf54dd965b832fc6f647859b19c09351828d3df767454769fca13f0640964a3fbacfcda706f88e8036556bc50bcd9d2e0217ca357352d5d0464edcfc3325b6efeff6dc610edf1f97a10abdab8ada6d042134fd399d0ef95b792cc46f6996f22a4d7a30cbdb81c84531e27a60ff56f2e652c2e4c48954b3055739f89a5c5e8e0163a483f561f0c71819e11faa864324094739d90de3efaa07abdb3c37046ed56a0f08b6e422c916bdb19efb7e46b49cac80de22fbe33c98c387fd1dce422d7c07a644a6078a5f92a241b80486a2317efeddfd3b7d99f6b3746f4ace88bba510931936b5b5f5bb3d18844d54093164dd77ca1d92261dba2ca19e93aa43691ae3006eb515644dfb1ccd59b95a6efc2a4c29bee997f6250755a7df479ac9296acfe661d6ad60690f4ca775e19f75f67d7cecd7e2e765ea701ab76bd2df53659389f4e80399d7f6641af6f5264d1723895039ba7968e767faa1c11917b5a37efcc2e72305d0f5ae922dba78939a6babaac5a2510fe3cbb3a06f0688172db5469d2fb8bf07abada75485d1ef5b94f47c66d6a0f3cbd64d0d7dd18a73566ea9943be9cc1ffa372c0b0d967e7c60bd5fbbbe38f11a5618c462a1a8fac9371ced5222ffbd1c78a6188d2ed62bfee41d175047e18e3dc
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148404);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/02");

  script_cve_id("CVE-2021-3449");
  script_xref(name:"IAVA", value:"2021-A-0149-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Tenable.sc 5.16.0 / 5.17.0 OpenSSL DoS (TNS-2021-06)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable.sc application installed on the remote host is version 5.16.0 or
5.17.0 and affected by the following OpenSSL denial of service vulnerability:

  - An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a
    TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial
    ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result,
    leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation
    enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1
    versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not
    impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j). (CVE-2021-3449)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-06");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2021041.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c531f5e9");
  script_set_attribute(attribute:"solution", value:
"Install Tenable.sc Patch SC-202104.1 or update to version 5.18.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3449");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

if (app_info.version !~ "^5.1[67].0$")
  audit(AUDIT_INST_VER_NOT_VULN, app_info.app, app_info.version);

var patches = make_list('SC-202104.1');
vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

vcf::report_results(app_info:app_info,
                    fix:'Tenable.sc Patch SC-202104.1',
                    fix_version:'5.18.0',
                    severity:SECURITY_WARNING);

