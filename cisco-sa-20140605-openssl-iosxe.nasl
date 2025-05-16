#TRUSTED 75e4ba258866a04f7c3d6452ba386cdc9d0e12182bc79209a7f8f0c19ec3de6ed969ad496949bd04c75293c4cfb96306a7b032cef182c26ff7d50097224b92327920ffad15a2b303aef33a513a1b3760ec063d6a1b4820f99620e56234a88cddbc270523f48f3d1fb1edc0c26dfafb0a351ca1c59451d661fd6582d288fd6a238f17798842c79d148640542bf192b880106a003e876783c7000b96db2fa1f663c45524881947c3691004f55e7ccff394916a69b1ce68df16a6108530f9001344f199c05ece596da7fd78d87dc6a3a3d2fb6ffe93b53c0368035cd2e723cd59299b3a6401498313f199fb74ab05a3785a5e880f92887dcaaafedea729b157a11c62ac4d6c0660451c62c7506cfa9c623c223623e921cb297722924c5ba0f04e95d48b5a8f97d8e92d700bd668f68cee1962b93a830725dab4b8281e276c75beed27551d930bc8273fb92e9a4f2e67f78beedd274edcab105e2a75fc680f43067db337e171a4a3a75f77317fdb39f5ded0e235d299f8beaf3792976ece24201d8f7562620cbdee7f793e1658f5bc18c64d95b04e4e6a6cae0cdcf23f61d3f64eebee2db8225d7e3407663a970da5f799e9c9a3c4cc09c216bc53e226031ea04158dcd6587bbd2122d59afc30eafbfb4c2e9e10fcb6d0c4ce8d9dab2762b008abb231a1aab9bca88c92bff7c65e50d866a88d30e709f4ba097f6398fd07de4d61cc
#TRUST-RSA-SHA256 19ae01d7dedfbc145a4105f879b8949e5b896c7f12979174629f2cc54618de29dbc188e2f08a095f53ea2af3607a490e56cf6e1ad4ac158fefefaba2280b5eccda2dff46c137bb32f32d5d1432a7125105e0158dbbe3e5813c8e1f18450998fbbb445d4fba75fafa4728ef234f151735cbbce8464f39c834e41e473d9c671873a183af82b5674f1f7366ce7afdf267af47b01ad841477a04bd416416e6ef8c6dee1cce219d5dc5453f9cbf103cc72c9f37f76c5e33c52e38f92b0836097fb0de4c7e39b844994c7bb6c0b7376f15e16a28507c5b96c9750a994ddcef982906683120664eff9db59b7a3b669fec5d5f6dc2c6927438dc793886bfed84dae41e6af1597ac77d7d9faa66ff39da777a8568b24efa7f05d57c663a4b02d22fe0defdf28b28eedb0926389fef791883beab12d205bb92254410bedc6df7ee6d71fadcef14f78e90c6dbf8d7b9571f6ab9e95176ce97f8f9d93e7b8f6afd2b5808d25f1086e58f5e980914385cc1b0e0e04a442ce1c4a20253333380f72653a82a8e17d139ebae82aca3bfb59b1050affe32f388986d1a44a48317bf9346531e2964d13360b14344ad9dab37a7aeff90b91108675193fa5ad09baff162c988a0f0d7d87715dd8135bc39b926780f5e077c26df1c6f7407fe0232f05f3b4d11127e6eaf886df4d74cc36a261f6a04ba766a2b8f2425f04bcf58ced615584a068e3db1fe
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88989);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0198",
    "CVE-2014-0224"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67899
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22487");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140605-openssl");

  script_name(english:"Cisco IOS XE Multiple OpenSSL Vulnerabilities (CSCup22487)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and its web user interface is configured to use HTTPS. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - An error exists in the ssl3_read_bytes() function that
    could allow data to be injected into other sessions or
    allow denial of service attacks. Note this issue is only
    exploitable if 'SSL_MODE_RELEASE_BUFFERS' is enabled.
    (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An error exists in the do_ssl3_write() function that
    could allow a NULL pointer to be dereferenced leading to
    denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An unspecified error exists that could allow an attacker
    to cause usage of weak keying material leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aa6a7e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup22487");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup22487.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

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
flag     = 0;
override = TRUE;

# Only 3.11.0S, 3.11.1S and 3.12.0S are affected
if (version == "3.11.0S") flag++;
if (version == "3.11.1S") flag++;
if (version == "3.12.0S") flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all", "show running-config all");

  if (check_cisco_result(buf))
  {
    override = FALSE;

    if (
      # Web UI HTTPS
      preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE) ||
      # SSL VPN
      cisco_check_sections(
        config:buf,
        section_regex:"^crypto ssl profile ",
        config_regex:'^\\s*no shutdown$'
      ) ||
      # HTTPS client feature / Voice-XML HTTPS client
      preg(string:buf, pattern:"^(ip )?http client secure-", multiline:TRUE) ||
      # CNS feature
      preg(string:buf, pattern:"^cns (config|exec|event) .* encrypt", multiline:TRUE) ||
      # Settlement for Packet Telephony feature
      cisco_check_sections(
        config:buf,
        section_regex:"^settlement ",
        config_regex:make_list('^\\s*url https:', '^\\s*no shutdown$')
      ) ||
      # CMTS billing feature
      preg(string:buf, pattern:"^cable metering .* secure", multiline:TRUE)
    ) flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override = TRUE;
  }

  if (!flag)
    audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");  
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCup22487' +
    '\n  Installed release : ' + version +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
