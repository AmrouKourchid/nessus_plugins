#TRUSTED 7fbaaf359a2cdab28cae432f97d371b58da1066a671ce45b61ee9cdaa502ca4a80dbba1136867e0898fbb01b4e5e9bc23ca436ebffcd52c7415c15f60dee6a47d5fe6b934a768227fcd427f9b619ea5cbc02d158e11c03581bb8dc14a173b20fc7198657cf0b020be688641dfdf2385370ec55dd78564407a794dfdf36a3bdf77a4f02ecd01cf9a0525f563a0ff606d60f03d541af076ddd878f25a2eb693dea1c6cf5494fb7d0b0bf547ce6a41eaca910e894added54dd8ebcc5e5cc281951dae3143fd39ff69e25493bfe3d6ad40c8d8ad602548e5c8ccf37a860fcb2a571e14c3396a3ef7157495419cbe8b82a36d0785d385f2700ab1fa32c49aab9ee31695922f8c9db02f0d001808be9d35ba7760809e8bcec44c0a141973e1b26c65023cdfac47fa64dcb66e6bfaa4a0e536fb53d8180f145e7c385d4c2bfc9ef3ecfdc41456ef51529c7c9782721479a0db8c1f890b21bf74fe48111738d0af12f4afb86de991246c01b163f710237771637834675ef91b1158fc6a83c0663da609349b67559977f0b071cf9c363b8ba0fbc031b844edf3bc05d7105a2434218949ad64ec25620d6f7df51211cefc0652c00810d941ea9e7f214281a42cdc816eeb5a39ad2dfc76deec5dfeee1eefe501c95bae7c9ae7e6355479dd88ccec3c5f008f700253fe51abc99600f7ab519d33fd58cc05258793adbafd07aa9251667038fb
#TRUST-RSA-SHA256 afa08212419792c5d222e2cd48dd38b4d82a38e509291b2e3bf520cd46101c60d462e955a2885f94bf3b4d5d17edcdd82880ded857cbc233d2da7218ba824cb1cd33aa3a0ba538399c2220e0de5482ce7a1e8afae41b90ad9ded6149675828d2251a10fd85fa7b6f0dc0610a66578c6eb3a3fbd25dee3e9d169a4bdf4d6ececc1f18fa1b8e3e3de97224e20268441d56badd162f9f351e0ff21c8fe9091589875adb4d5d59f1235ebca0c63bb3d6f4e3b5f67dd9797ab4b8ed0b422f7e5aa136107fa57c108d93aec291144d7db2c16b4d222822149798e24679597103297c5256b2e33e4a13f92a9c665446bb71b5d50c04793c63f82b5fadbcdfec3d5d273192d08a95ffd5a2e2cd646fcb81ca31b101d72ebe342271559ff9f6cdfb1813849ee00173118f40c9540e59259330e4f832acecaf8dbb3db2c39e5280d1a90db57b75e3099d59a8b1717c7e1453364f20d45f3efb892a151678aee757beccfbe3d92ce4a142fb7665776e38bbac392aafaa71832c7e114ce4ea42ecea72ec2541b50b8aa34f8a9713ea41b46250f626e812d160b01b57e571fbf09c0b59299f885a691c39b78dbda4b478c12d276173a9ea0a3e4f64980bc4cff4412220ebb7d042963436c805708e83e11043de5bbac4f97a88995f99a72d70ff26c503dbf16318c86f7baed676462ad5c834c186262c26669f051e177860b01e90c44cfb5ebf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87242);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_name(english:"TLS NPN Supported Protocol Enumeration");
  script_summary(english:"Enumerates TLS NPN supported protocols.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host supports the TLS NPN extension.");
  script_set_attribute(attribute:"description",value:
"The remote host supports the TLS NPN (Transport Layer Security Next
Protocol Negotiation) extension. This plugin enumerates the protocols
the extension supports.");
  script_set_attribute(attribute:"see_also",value:"https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");
  script_exclude_keys("global_settings/disable_ssl_cipher_neg");
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("ssl_funcs.inc");

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers per user config.");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

exts = mkword(13172) + mkword(0); # Extension type + empty extension data

if(pp_info["proto"] == "tls")
{
  versions = get_kb_list('SSL/Transport/'+port);

  cipherspec = NULL;

  tls10 = tls11 = tls12 = 0;
  if(! isnull(versions))
  {
    foreach var encap (versions)
    {
      if (encap == ENCAPS_TLSv1)              tls10 = 1;
      else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
      else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
    }
  }

  if(!(tls10 || tls11 || tls12))
    exit(0, 'The ' + pp_info["l4_proto"] + ' service listening on port ' + port + ' does not appear to support TLSv1.0 or above.');

  # use latest version available
  if (tls12)       version = COMPAT_ENCAPS_TLSv12;
  else if (tls11)  version = COMPAT_ENCAPS_TLSv11;
  else if (tls10)  version = ENCAPS_TLSv1;

  ciphers = get_valid_ciphers_for_encaps(encaps:version, ciphers:ciphers);
  if(is_ec_extension_required(cipher_set:ciphers, encaps:version))
    exts += tls_ext_ec() + tls_ext_ec_pt_fmt() + tls_ext_sig_algs();
  cipherspec = get_cipherspec_from_names(ciphernames:keys(ciphers));

  recs = get_tls_server_response(port:port, encaps:version, cipherspec:cipherspec, exts:exts);
}
else if(pp_info["proto"] == "dtls")
{
  cipherspec = dtls10_ciphers;

  version = COMPAT_ENCAPS_TLSv11;
  foreach encap(versions)
  {
    if(encap == COMPAT_ENCAPS_TLSv12)
    {
      version = COMPAT_ENCAPS_TLSv12;
      cipherspec = dtls12_ciphers;
      break;
    }
  }

  exts += tls_ext_ec() + tls_ext_ec_pt_fmt() + tls_ext_sig_algs();
  recs = get_dtls_server_response(port:port, encaps:version, cipherspec:cipherspec, exts:exts);
}
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

report = FALSE;

info = ssl_find(
  blob:recs,
  'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
  'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
);

npnprotos = info['extension_next_protocol_negotiation'];
if (!isnull(npnprotos))
{
  foreach var proto (npnprotos)
    set_kb_item(name:"SSL/NPN/" + port, value:proto);
  report = '\n  ' + join(npnprotos, sep:'\n  ');
}

if(report)
{
  report = '\nNPN Supported Protocols: \n' + report + '\n';
  security_report_v4(port:port, extra:report, proto:pp_info["l4_proto"], severity:SECURITY_NOTE);
}
else
  exit(0, "No NPN extension protocols detected on " + pp_info["l4_proto"] + " port " + port + ".");
