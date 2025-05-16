# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ssh_sha1_hmac.inc
#
#
# Revision: 1.1
#

namespace ssh_sha1
{
  function get_macs(port, type)
  {
    var alg, algs, macs;

    macs = make_list();

    algs = get_kb_list('SSH/' + port + '/mac_algorithms_' + type);
    if (isnull(algs))
      return macs;

    algs = make_list(algs);
    if (max_index(algs) == 0)
      return macs;

    foreach alg (algs)
    {
      # hmac-sha1
      # hmac-sha1-96
      # hmac-sha1-96-etm@openssh.com
      # hmac-sha1-etm@openssh.com
      if ('sha1' >< alg)
        macs = make_list(macs, alg);
    }

    return macs;
  }
}

