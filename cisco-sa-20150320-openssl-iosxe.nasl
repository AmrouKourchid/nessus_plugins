#TRUSTED 50c34eaf9b729bd602b8857a2a9019ca6627f450c933bca759d0613096e8b6ba075ed6e28b399ff90188d1352091149fc0d47a8532e99f3a201ec75ac94db11390d2138bb630876c557493e9f3a722ad1c621c51211c114d0b4ee3563abc47f2c8c6701f1fe75b407ba9b02adc7ff4f60e9a15ef3d7e6e0898ae03580106c2f0932e95eaea7b0f1a7b20867cf3895d9e78d8f7a9aa6fc90eb8f762befe95a4cf358be2cd5880ecc19a498d547e5eb8d3517540cd78d3153bededfbbcaf9872706a60a4d994d768683faa8c69678b810b07fa46a1a5bd629d45d6b60f919e993968079d28a5bab7794ddd7e6ce79382d6a9ffe87a1dd0f0f3652446d936438459b7eb4a2f600da9ec281b46568ed701ad3682eabfba3d01c8b367bbe20b8a45c67bca906113f818d4cf1ed7133183877d8a6352715e031e02254c4e66356003d89968538b2368f2d9e71c3039d48f338a7ee94841d0f57b17aa150ce5c63eb70fa4f5f7eb59280e1ab10becad0b3442441e7dfdb51429620c0c2e572f4b0495cc4e6433344e9ab85c5e3b32c82022d404c6547779eb61df0ad2e7a56713ff96ede623ac573c513191f98347e7c178dfcd00cc68cf0c10ab91d2b24f9ffd1c8e76c0012f3e83b7c3c0dff5bab54d0ce05f336b9d1204664d2e51609e18fa3e43e71bfd15b1f04067482bb8ab5af6642c30006fcf378597bf24d71f1762e8826aae
#TRUST-RSA-SHA256 23b59fea6b3e4ea67b79acef58970f27564518dace23f0adeb819fb4f4048872d0849e2344db038c040ffdb06ae83c6957f960ec2ace937ea0a2cb4a32a4203041c83ab37c13cf0e138bafeb70c6f30aa612e407d281dcc7c32467999c626b81f722176f8d4b4aae4c397dca6b4c8aecae528bc40ba708bd37b41e0128c5d594e0f580b06694b4a98e8ab9b13d8ae2ba2f7cceeaa52c67ee903658e6a044b2a7ec339d135434464c52256652b1339218b0a16b476090f27d8049bf4f3b2a127313f0ef0c078aeef553b5e7218686301a29ca0bdfb553ad8b55a708daf8cc93a3f3a8da2df2e797a633c3f48ea0cb197df2408311326d53b304ade31d0394e15bf65080fd9ae9e2f66ac6bdb8c94b467fcf52adee626c69a9dc4625ed8932128fa0f521162bded687acb920ea4bc603b1f2710a6098b484aefd6f29fe509dd5bc1a7e05dc0be5c5efb748791aab808e6da66a391eac5ab863945069ae961b9aed1616f3d9ad9af81b6e1f2f128c496a2551459f4b1ea983d99f7a8e1ca98ad76d328195f491af37976faf9daea1495719670b5aa460bfe46e125e520b97f7ad55e636857565baaf28c8476e5a7d5c13a63420869e138fc8140945c44a9ea104ec7835722a98913cd40dfc2edcae6240b48615d3e121d33518c34f06ad55f3c98a932d93ae8cd7ff54d8943fd519e1cbbda836562b1ad994fbd9c786b8d85db977
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90526);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-0293"
  );
  script_bugtraq_id(
    73225,
    73227,
    73228,
    73231,
    73232,
    73237,
    73239
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCut46130");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut46126");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150320-openssl");

  script_name(english:"Cisco IOS XE Multiple OpenSSL Vulnerabilities (CSCut46130 / CSCut46126)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch and has an IOS service configured to use TLS or SSL. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

  - An invalid read error exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150320-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2beef118");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut46130");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut46130.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
##
# Examines the output of show running config all for evidence
# the WebUI is running and using SSL
#
# @remark 'override' in the return value signals that the scan
#         was not provided sufficient credentials to check for
#         the related configurations. 'flag' signals whether or
#         not the configuration examined shows the webui with
#         SSL is enabled
#
# @return always an array like:
# {
#   'override' : (TRUE|FALSE),
#   'flag'     : (TRUE|FALSE)
# }
##
function iosxe_webui_ssl()
{
  local_var res, buf;
  res = make_array(
    'override',  TRUE,
    'flag',      TRUE
  );

  # Signal we need local checks
  if (!get_kb_item("Host/local_checks_enabled"))
    return res;

  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all",
    "show running-config all"
  );

  # Privilege escalation required
  if (cisco_needs_enable(buf))
    return res;

  res['flag'] = FALSE;

  # Check to make sure no errors in command output
  if(!check_cisco_result(buf))
    return res;

  # All good check for various SSL services
  res['override'] = FALSE;

   # Web UI HTTPS
  if (preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE))
    res['flag'] = TRUE;

  return res;
}

##
# Main check logic
##

flag = 0;
if (version == "3.11.0S") flag++;
if (version == "3.12.0S") flag++;
if (version == "3.13.0S") flag++;
if (version == "3.14.0S") flag++;
if (version == "3.15.0S") flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);

# Configuration check
sslcheck = iosxe_webui_ssl();

if (!sslcheck['flag'] && !sslcheck['override'])
  audit(AUDIT_HOST_NOT, "affected because it appears the WebUI is not enabled or not using SSL/TLS");

# Override is shown regardless of verbosity
report = "";
if (report_verbosity > 0)
{
  order  = make_list('Cisco bug ID', 'Installed release');
  report = make_array(
    order[0], 'CSCut46130 / CSCut46126',
    order[1], version
  );
  report = report_items_str(report_items:report, ordered_fields:order);
}

security_hole(port:0, extra:report+cisco_caveat(sslcheck['override']));
