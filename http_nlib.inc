#TRUSTED 9f6256c69e03b4bf68def7a76262af412d4a4f297b5bfa520f5f8538f077d467549a6cdd911ec32adb8d1c989b28c1a8d0a37509d7812387eda2c50b964314416b1d8aa0666b9ab3a150abc78f06d2058ba89c0466360b064b1ef9444f970c663429cca92d6f40cb7960b9e8cf194fd1d33ca4f5c9f0bf5e1b5279022d5a341da3aec01a80d216f561966d03b3e53bedde46c022de596cf1cc0b416240eb4525daf6d95d829ec05e1b9b6e1d154265593c90bf015fc1c14f6af4b2fb0323dbd97c2803447dd082b943cfc4319adc55026ca4a8063597a0a165920dca061d4095f1bea5b2a993fcae7aeb2d070eea32afc79cb630c3ecc1dd2bc5aa2e099b52e0270c2cce998bdd1d24cdbb5185e82e250d4b7b94e872202ccede6a5ee7a3f8a57c76086795e7c53ad0465c16abb4baceb72cb160f36a35f73f1d2bd99c15a5d61881203618033c5e2c6724d0e4992ad764b3327ad3076fa41d8d46af3167365c964444277939ab710b527473549a333c78a181ac01a5b8e04fc9a7c405cc8aaed35120edaf2de46e42286e75a3ce0ebf2ba49c7f8a0b3ebf2b73ebc2c9e29598d0cfc211134079b05bc6a966388ecad748a8f846eaec69467afa967788e844dbd29effa18b9a39aaf925f9a86929df8eea41d71a914b224862aae4532eb854d1bd52972f0ac85298163d954bf376dd4129646c6378df0bb37b3259f0650a13c0
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# http_nlib.inc
# Revision: 1.1

include("compat_shared.inc");

function parse_http_headers(status_line, headers, sep)
{
  local_var	v, line, s, k, err;

  if (isnull(headers)) return NULL;

  v = make_array();
  err = 0;
  foreach line (split(headers, keep: 0))
    if (strlen(line) > 0)
    {
      s = pregmatch(string: line, pattern: '^([A-Z_][A-Z0-9_-]*)[ \t]*:[ \t]*(.*)$', icase: 1);
      if (isnull(s))
      {
        debug_print('parse_http_headers: cannot parse HTTP header -> ', line);
        err ++;
        continue;
      }
      k = tolower(s[1]);
      if (isnull(v[k]))
        v[k] = s[2];
      else
      {
        if (isnull(sep))
        {
          debug_print('parse_http_headers: repeated HTTP header ', s[0], '\n');
          sep = ',';
        }
        v[k] += sep + s[2];
      }
      # No use to call chomp(), split(keep: 0) already removed \r\n
    }
  if (status_line)
  {
    v['$status'] = chomp(status_line);
    k = pregmatch(string: status_line, pattern: '^HTTP/[01]\\.[01]+ +([0-9]+) ');
    if (! isnull(k))
      v['$code'] = int(k[1]);
    else
    {
      debug_print('parse_http_headers: cannot parse status line -> ', status_line);
      err ++;
    }
  }
  if (err > 0) v['$errors'] = err;
  return v;
}

