#TRUSTED 59b812cbe11fa13e86bd49e23b335b5428c28beaed8fda6ea4fd729877f9d56c4b1b127b1d890881151fd6172b57140fc10277142e23db33f79021ee00febd6aac53d23f7bdb1b46bece8a4826be580c738ec9233afc523524111566c817ad134d068aa7dd720ed291716dcc9c2517f9439ac6df06c81b5745edcd4e7e27f42aa476567088fa921cd15e87766bdb3b42c181541760bb7be49599a5e0a0cc3bd085ea647bd496b776f3a3f1471bd6fd5248cbecb1ad20c65aef5c99debfd5786ab70dd4ff376d2410e2202328fbe4a8ad3c579cb274aa7e0e0ccb62815ec2e110fdd23de4531aa1974591045da69acc812bbd1065223023352a32dd9f33edcf0aec98ecbac05130025da0d6750d8932c451ae7c6a448ece5302482c5ca140dd8465662695916cfabebc65228ba324878e43b30e6eb263e55581837a1aa4ebca4875e38503e8828523e4d9e5fad4b6be6c02ff5f9461c507a11e40e40f5f4521a6bc0bdefe04b82fea6275ce0d872255281f289144434476c826ecc2d5b2c1da971fb79eb61d9d6085df40a9f4fe12932f160fc7c3f3586cdcd3d506309cce65385afd03670f3bafab70d3e5cadb0163b10d990f56917af965f4f6714938f50732fe415fffdd0b30d43f0e9217317bf57daf9e86fd543116f5226b96136c227e6882b3421af429003066e3e5f474ebcabee9535b83ee9b9a050304e09eeaf54c98
#TRUST-RSA-SHA256 29d3138fd39c136ee82a783e6fdd2750f20ca37a6d931b073419d41f8789a9a7fbc68e3c4b1b3567b201fac6c6d0d85cf815a56f6e1167c7633d449faa0a8f44f9e16a191b34f4c16247887a1aac858d0f94d0fab589e898b12e92539dcfb5eb80a12932c2f73c915d3cf898a1c5feb88024732c08c0702f2b90b4d68414417bc87300f7caa5c52abc71093a051deecb2c0ee35ca00d7fa71005ddd3e3a3870687b3b9da0e9cca2c97b801c80e48307fb4ded3fa114fc0a454453faba23d8d1f36ebfdf9a8d4eed55259e727681893f55beaa8500256d48cc8cada1c7f96f11fdf3ef5cb4e880011e444bbb62d90eb1adcddaff859b26430fe89ae4d404f521800d8ebd2f2386549a916adcd98cd39d838bfa02839b8477c5bf977ccd47e08e895b06ee2d1dbd901390d111f37c94682ebe2ea44135d11a46fb70828a9a895e4de58357e511c8686df46f97e6036dda7ba7755ad90869928eb0e9b2c4df19aa2f305319a74ecf69f62e5e8676a6304f62c925d8a3d96bdfb2ce0cb870029e3ad1f63f120710dd5e912c0869914110c8f769861931182f02c7fecacb4aa98cc45e8e25b7354ac64d4e12cda7565bb7cf6315a356edad92ae50f3f4fa969a245a5010931f967ae723a7ceef58af604d996105e2910218eed26c7065ead8aa9a181619cd6db89cd9f257eb80ba4865d703f6d1db34af41c52d678a29a848ba39fed
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83875);
  script_version("1.41");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host allows SSL/TLS connections with one or more
Diffie-Hellman moduli less than or equal to 1024 bits.");
  script_set_attribute(attribute:"description", value:
"The remote host allows SSL/TLS connections with one or more
Diffie-Hellman moduli less than or equal to 1024 bits. Through
cryptanalysis, a third party may be able to find the shared secret in
a short amount of time (depending on modulus size and attacker
resources). This may allow an attacker to recover the plaintext or
potentially violate the integrity of connections.");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the service to use a unique Diffie-Hellman moduli of 2048
bits or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"An in depth analysis by Tenable researchers revealed the Access Complexity to be high.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");

  exit(0);
}

include('byte_func.inc');
include('ftp_func.inc');
include('kerberos_func.inc');
include('ldap_func.inc');
include('nntp_func.inc');
include('smtp_func.inc');
include('ssl_funcs.inc');
include('telnet2_func.inc');
include('rsync.inc');
include('debug.inc');

if ( get_kb_item('global_settings/disable_ssl_cipher_neg' ) ) exit(1, 'Not negotiating the SSL ciphers per user config.');

if(!get_kb_item('SSL/Supported') && !get_kb_item('DTLS/Supported'))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

var oakley_grp1_modp = raw_string( # 768 bits
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
);

var oakley_grp2_modp = raw_string( # 1024 bits
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
  0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
  0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
);

var encaps_lookup = make_array(
  ENCAPS_SSLv2,  'SSLv2',
  ENCAPS_SSLv23, 'SSLv23',
  ENCAPS_SSLv3,  'SSLv3',
  ENCAPS_TLSv1,  'TLSv1.0',
  COMPAT_ENCAPS_TLSv11, 'TLSv1.1',
  COMPAT_ENCAPS_TLSv12, 'TLSv1.2'
);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
var pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE, ciphers:TRUE);
var port = pp_info['port'];
if (isnull(port))
  exit(1, 'The host does not appear to have any TLS or DTLS based services.');

var supported;
if(pp_info['proto'] == 'tls')
  supported = get_kb_list_or_exit('SSL/Transport/' + port);
else if(pp_info['proto'] == 'dtls')
  supported = get_kb_list_or_exit('DTLS/Transport/' + port);
else
  exit(1, 'A bad protocol was returned from get_tls_dtls_ports(). (' + pp_info['port'] + '/' + pp_info['proto'] + ')');

var cipher_suites = pp_info['ciphers'];
if(isnull(cipher_suites))
  exit(0, 'No ciphers were found for ' + pp_info['l4_proto'] + ' port ' + port + '.');
cipher_suites = make_list(cipher_suites);

# declare all vars used in foreach loops below
var report, encaps, ssl_ver, v2, cipher, recs, skex, possible_audit, fn, mod_bit_len, dh_mod, known_mod;

report = '';

foreach encaps (supported)
{
  ssl_ver = NULL;
  v2 = NULL;

  if (encaps == ENCAPS_SSLv2)
    ssl_ver = raw_string(0x00, 0x02);
  else if (encaps == ENCAPS_SSLv3 || encaps == ENCAPS_SSLv23)
    ssl_ver = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1)
    ssl_ver = raw_string(0x03, 0x01);
  else if (encaps == COMPAT_ENCAPS_TLSv11)
    ssl_ver = raw_string(0x03, 0x02);
  else if (encaps == COMPAT_ENCAPS_TLSv12)
    ssl_ver = raw_string(0x03, 0x03);

  v2 = (encaps == ENCAPS_SSLv2);


  foreach cipher (cipher_suites)
  {
    var exts = "";
    if(is_ec_extension_required(cipher_set:make_array(cipher, ciphers[cipher]), encaps:encaps))
      exts += tls_ext_ec() + tls_ext_ec_pt_fmt() + tls_ext_sig_algs();

    if(pp_info['proto'] == 'tls')
    {
      recs = get_tls_server_response(port:port, encaps:encaps, cipherspec:ciphers[cipher]);
      fn = 'get_tls_server_response';
    }
    else if(pp_info['proto'] == 'dtls')
    {
      recs = get_dtls_server_response(port:port, encaps:encaps, cipherspec:ciphers[cipher]);
      fn = 'get_dtls_server_response';
    }

    if(strlen(recs) == 0)
    {
      dbg::log(src:fn, msg: cipher + ' on port ' + port +
                                    ' : ClientHello handshake was empty or null. Possibly timed (10 seconds)');
      continue;
    }
    else if(strlen(recs) > 0)
    {
      dbg::log(src:fn, msg: cipher + 'ClientHello handshake on port ' + port + '\n' + obj_rep(recs));
    }

    # Server Key Exchange
    skex = ssl_find(
      blob:recs,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
    );

    # Server Key Exchange, additional debugging
    if (!empty_or_null(skex))
    {
      fn = 'ssl_find';
      dbg::log(src:fn, msg:cipher + ' on port ' + port + ' :\n\t' + obj_rep(skex));
    }

    possible_audit = '';

    if (!isnull(skex) && strlen(skex['data']) >= 2)
    {
      skex = ssl_parse_srv_kex(blob:skex['data'], cipher:ciphers_desc[cipher], version: ssl_ver);

      # After parsing the server kex, dump additional debugging info
      if (!empty_or_null(skex))
      {
        fn = 'ssl_parse_srv_kex';
        dbg::log(src:fn, msg:'Parsing Server KEX data for ' + cipher + ' on port ' + port +
                              ' :\n\tGenerator (dh_g) = ' + obj_rep(skex['dh_g']) +
                              '\n\tPrime Modulus (dh_p) = ' + obj_rep(skex['dh_p']) +
                              '\n\tPublic Value (dh_y) = ' + obj_rep(skex['dh_y']) +
                              '\n\tKEX (kex) = ' + skex['kex'] +
                              '\n\tSignature (sig) = ' + obj_rep(skex['sig']));
      }

      if(skex['kex'] == 'dh')
      {
        dbg::log(src:SCRIPT_NAME, msg:'Diffie-Hellman server KEX received for ' + cipher + ' on port ' + port +
                                      ' :\n\tProtocol: ' + ENCAPS_NAMES[encaps] +
                                      '\n\tCipher: ' + ciphers_desc[cipher] +
                                      '\n\tPrime modulus length: ' + serialize(strlen(skex['dh_p'])));

        if(empty_or_null(skex['dh_p']))
        {
          if(isnull(skex['dh_p']))
            dbg::log(src:SCRIPT_NAME, msg:'For ' + cipher + ' on port ' + port + ', Prime Modulus is NULL!');

          possible_audit = 'Invalid prime modulus received from server.';
          continue;
        }

        mod_bit_len = strlen(skex['dh_p']) * 8;
        dh_mod = skex['dh_p'];

        known_mod = (dh_mod == oakley_grp1_modp || dh_mod == oakley_grp2_modp);

        # Used by pci_weak_dh_under_2048.nasl
        if (get_kb_item('Settings/PCI_DSS'))
        {
          set_kb_item(name:'PCI/weak_dh_ssl', value:port);
          replace_kb_item(name:'PCI/weak_dh_ssl/modlen/' + port, value:mod_bit_len);
        }

        if((mod_bit_len <= 1024 && mod_bit_len >= 768 && ((report_paranoia == 2) || known_mod)) ||
            mod_bit_len < 768)
        {
          report +=
          '\n  SSL/TLS version  : ' + encaps_lookup[encaps] +
          '\n  Cipher suite     : ' + cipher +
          '\n  Diffie-Hellman MODP size (bits) : ' + mod_bit_len;

          if(dh_mod == oakley_grp1_modp)
             report +=
             '\n    Warning - This is a known static Oakley Group1 modulus. This may make' +
             '\n    the remote host more vulnerable to the Logjam attack.';
          if(dh_mod == oakley_grp2_modp)
             report +=
             '\n    Warning - This is a known static Oakley Group2 modulus. This may make' +
             '\n    the remote host more vulnerable to the Logjam attack.';

          if(mod_bit_len > 768)
            report += '\n  Logjam attack difficulty : Hard (would require nation-state resources)';
          else if(mod_bit_len > 512 && mod_bit_len <= 768)
            report += '\n  Logjam attack difficulty : Medium (would require university resources)';
          else
            report += '\n  Logjam attack difficulty : Easy (could be carried out by individuals)';
          report += '\n';
        }
      }
    }
  }
}

if(report)
{
  report = '\nVulnerable connection combinations :\n' + report;
  # temporarily adding report to debugging - remove later
  dbg::log(src:SCRIPT_NAME, msg:'Scan Report : \n\t' + report);
  security_report_v4(port:port, proto:pp_info['l4_proto'], extra:report, severity:SECURITY_NOTE);
}
else if(strlen(possible_audit) > 0)
{
  exit(0, possible_audit);
}
else audit(AUDIT_HOST_NOT, 'affected');
