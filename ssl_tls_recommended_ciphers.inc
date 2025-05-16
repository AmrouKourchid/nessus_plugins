# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ssl_tls_recommended_ciphers.inc
#
#
# Revision: 1.4
#

include('compat_shared.inc');
include('byte_func.inc');
include('lists.inc');
include('ssl_funcs.inc');

namespace ssl_tls_ciphers
{

  var RECOMMENDED_CIPHERS = [
  # TLS 1.3
  # 0x13,0x01
    'TLS13_AES_128_GCM_SHA256',
  # 0x13,0x02
    'TLS13_AES_256_GCM_SHA384',
  # 0x13,0x03
    'TLS13_CHACHA20_POLY1305_SHA256',

  # TLS 1.2
  # 0xC0,0x2B
    'TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  # 0xC0,0x2F
    'TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  # 0xC0,0x2C
    'TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  # 0xC0,0x30
    'TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  # 0xCC,0xA9
    'TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  # 0xCC,0xA8
    'TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  # 0xCC,0xAA
    'TLS12_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
  ];

  function get_discouraged_ciphers()
  {
    var ports_and_discouraged_ciphers = {};

    foreach var pp_info (get_tls_dtls_ports(dtls:TRUE, ciphers:TRUE))
    {
      var pp_port = pp_info['port'];
      var kbs = pp_info['ciphers'];

      if (pp_info['proto'] != 'tls' && pp_info['proto'] != 'dtls')
        continue;

      if (empty_or_null(kbs))
        continue;

      var cipher_list = make_list(kbs);

      var discouraged_ciphers = collib::subtract(cipher_list, ssl_tls_ciphers::RECOMMENDED_CIPHERS);

      if (empty_or_null(discouraged_ciphers))
        continue;

      ports_and_discouraged_ciphers[pp_port] = discouraged_ciphers;
    }

    return ports_and_discouraged_ciphers;
  }

}

