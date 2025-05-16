#TRUSTED 5608a2da71bf96ef6f1d551ad450970df7dd24a11ef766e611d3358a929fa774fe905922c20ba91e64e1ceb68e63b9436f6825db9481d7305a8e7dfd906f5d3b6148b541e27aa4b682599c02757afa66b5f71eb47cc0ff7651f128cf3200bcece6037beb4f75576a19f9c6c935f6bd08f16e99775c68e36a7e8cf9ef0dba6f519dd6e0868c92232e62cda04d1602e8991e401ba3943f35090e14f4f5dd1d026c440e270faa9e6b18e6cd2ea59a9c0d7e61008c04918555f268fefc213a6525c9640844178024633d0be20bb3ca4e11f45e2baeec7b7448a1fe742154320eb2e41205133a7c41c472321d100f01c7c041352fe51bcbfe74b81300f36d3741d72c6668e4f0e37509f102afb341077dd365f6d6f7e4ed10f546a5d7c2981d52d25fa5c4fe3bef1d2166e09dc9f7353a7d908809f6a25436004171d43a5becdb5e7dc8e54412a3406d801de24eb3ebbe6aec316f67bfe6e9193968dcb864686d60bc8e93f44ccb9d983f9c7d5f776f8786090de4b0e962ece613a4361a6845cf2de0e35b16c088f903ab7ff1316818a174621e84207a0c81cd841caaa3b347ab4c1e4cbce43417b070807fb8c7aa6bf50e623ecee2429b5540ce3e3f4f96632690e20f4d78acf6b7b7ace6804affab0588bb1f9bfd9a3851edecce8020e30fea0dc7729d9697fe6a9ad8420b26033355b24aa979c13230a7289f2beaa4908d9aa8b3
#TRUST-RSA-SHA256 61d8ae4cc1c367a2fddb50fcb53a55b6648dfee2575957f508348cf11d1b3039b32fe0f5e2257f7989c44977b577729eeea13b120e66d7d02727bd21e0142e23aa3535a81fe451cea000b8517cdadcb57bb4999ca50793c27e097b06dd0523d8f7fec7c084662f022f409fbaa2a44d4c961fa0b4db800e5dd0ce2d02dcc2295b3f5002cd266a4ef70d1cd9fc2be05be081c66c74d01b2dd951697700f2dd6264a12b49d36fd3a23aafce90e6ec5a4e1e556649060abd088f33aa0ea3bfcbb677f7f632d49bba19916a2483d78292d173013369107f5296cf00f2e99d77ee7d8889244dc644ed1b58cdbdefa91baf3cd7a634e207e697776052a077f29ea99b93aa24a25049177907f2001abbc772dc75d11f013885460d7ac2f8c636bc9d69750f6b1cdee278c9f0137baf346f7f453570c77c4c7824ef80a956bcafb31cd030894ed6e4a490c15464c2a73980ac3ddc496948f9c6e9ed3b0750964c8d7789cf1df2c41dd3b6db30892e359a2d8fc7fb9a229fd24681a83ca271788fa3d046df2f31c2b1e383dc5d4be875c9284139c09f4d95647ff7ad1b65201057a39b7211e16f3396fe46313add598a0bd9c5411715fd835b8a65f012d721b7fdb2b449068099fe3eec0ef739f3478c36af34c09325b4ce25a7cf88e3f0e15defe1b36d968a6f430c748f8e7cbeba259718f9ecb49e95edc97f4a266f41dc7fb0de790244
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93345);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2016-2207",
    "CVE-2016-2209",
    "CVE-2016-2210",
    "CVE-2016-2211",
    "CVE-2016-3644",
    "CVE-2016-3645",
    "CVE-2016-3646"
  );
  script_bugtraq_id(
    91431,
    91434,
    91435,
    91436,
    91437,
    91438,
    91439
  );

  script_name(english:"Symantec Protection Engine 7.0.x < 7.0.5 HF01 / 7.5.x < 7.5.3 HF03 / 7.8.x < 7.8.0 HF01 Multiple Vulnerabilities (SYM16-010) (*nix check)");
  script_summary(english:"Checks the version of Symantec Protection Engine.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Protection Engine installed on the remote
host is 7.0.x prior to 7.0.5 HF01, 7.5.x prior to 7.5.3 HF03, or 7.8.x
prior to 7.8.0 HF01. It is, therefore, affected by multiple
vulnerabilities :

  - An array indexing error exists in the Unpack::ShortLZ()
    function within file unpack15.cpp due to improper
    validation of input when decompressing RAR files. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted file, to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code. (CVE-2016-2207)

  - A stack-based buffer overflow condition exists when
    handling PowerPoint files due to improper validation of
    user-supplied input while handling misaligned stream
    caches. An unauthenticated, remote attacker can exploit
    this, via a specially crafted PPT file, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-2209)

  - A stack-based buffer overflow condition exists in the
    CSymLHA::get_header() function within file Dec2LHA.dll
    due to improper validation of user-supplied input when
    decompressing LZH and LHA archive files. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted archive file, to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-2210)

  - Multiple unspecified flaws exist in libmspack library
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these, via
    a specially crafted CAB file, to corrupt memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-2211)

  - A heap buffer overflow condition exists in the
    CMIMEParser::UpdateHeader() function due to improper
    validation of user-supplied input when parsing MIME
    messages. An unauthenticated, remote attacker can
    exploit this, via a specially crafted MIME message, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-3644)

  - An integer overflow condition exists in the
    Attachment::setDataFromAttachment() function within file
    Dec2TNEF.dll due to improper validation of user-supplied
    input when decoding TNEF files. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted TNEF file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-3645)

  - An array indexing error exists in the
    ALPkOldFormatDecompressor::UnShrink() function within
    the scan engine decomposer due to improper validation of
    input when decoding ZIP files. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted ZIP file, to corrupt memory, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-3646)");
  # https://support.symantec.com/en_US/article.SYMSA1371.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76c14f65");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Protection Engine version 7.0.5 HF01, 7.5.3 HF03,
7.8.0 HF01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3646");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:protection_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_protection_engine.nbin");
  script_require_keys("installed_sw/Symantec Protection Engine");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_lib.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


enable_ssh_wrappers();
report = '';
app = 'Symantec Protection Engine';
port = NULL;
function check_hf(path)
{
  local_var cmd, ret, buf, match, ver;
  local_var line, matches, vuln;

  vuln = FALSE;
  cmd = "cat -v " + path + "/bin/libdec2.so";

  if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  port = sshlib::kb_ssh_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

  ret = ssh_open_connection();
  if (!ret) exit(1, 'ssh_open_connection() failed.');

  buf = ssh_cmd(cmd:cmd);
  ssh_close_connection();

  if(!empty_or_null(buf)){
    match = eregmatch(pattern:"Decomposer\^@(\d\.\d\.\d\.\d)",string:buf);
    ver = match[1];
    if(ver_compare(ver:ver, fix:"5.4.6.2", strict:FALSE) < 0) vuln = TRUE;
  }
  else audit(AUDIT_UNKNOWN_APP_VER, "Symantec Protection Engine: Decomposer Engine");
  return vuln;
}

install = get_single_install(app_name:app);
version = install["version"];
path = install["path"];
path = chomp(path);

fix = NULL;

if (version =~ "^7\.0\.[0-9.]+$")
{
  if (
    version =~ "^7\.0\.5\." &&
    check_hf(path:path)
  ) fix = "7.0.5 HF01";

  if (version =~ "^7\.0\.[0-4]\.")
    fix = "7.0.5 HF01";
}
else if (version =~ "^7\.5\.[0-9.]+$")
{
  if (
    version =~ "^7\.5\.3\." &&
    check_hf(path:path)
  ) fix = "7.5.3 HF03";

  if (version =~ "^7\.5\.[0-2]\.")
    fix = "7.5.3 HF03";
}
else if (version =~ "^7\.8\.[0-9.]+$")
{
  if (
    version =~ "^7\.8\.0\." &&
    check_hf(path:path)
  ) fix = "7.8.0 HF01";
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (!empty_or_null(fix))
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
