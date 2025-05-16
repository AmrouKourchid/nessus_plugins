#TRUSTED 537f89a657dbed7c37caef25a9445b282b4e576cd084da6f853648865bfb9aff3cc8b65cf575a6ffa068d9aec24abd734f00ae35c11123f25e9095b8b47d3f07b21df81cd958e04012b2fd1b78111921b165ff75e3a7126b14fdde7c89048f0df5846b7f98a3de218f49c96c85835afc730a43bd9ba67a0bbb39b1c9f09e5d1453be70626f5323fdbabbd5def7e75dd2047809ad4d1691ea19ae7661718f146ef6cf2229d9633fc63874d7977ecdf613bcad32a60107fcdac03c7cad0c275ce46e856b17311f3b16816dcb1daf2e812ec9789c31e64851d2c3d27f05166dfef546097a8899d5f8cd4d747158196519932268e03fc8fe16f38259f76704a363bc1e258b5a3c3efc3e66ddc405d4840143933552138aceb7989294f612b3afc223ab66f77bab703b2a31a683994e059e6f427f8a04a20056a7aaee41cb68346245aab5cbd1d2f208d918f9958f8cfc51e6fe7c4f32ac7acca5395e5e502b844c62e4650dacb1fcc4d933ca900662f89f390f33ed76b454d373866a36d647e2ee783475123b7126e790d7a366ecb09b6b9ae95892d5086a0111776c1ead55743f4e804dbf3017b07e0a0bf7f9415a7722e3a3d8a16d64a2732d753d30508fabf917203f888f404f8490dc71d85091e2b14e7124947e7dd83eb512370808614631472024a3e3b80b4e5e7347036c482250250c5e813aa11b5487e7453cef5b0446fb
# Mapping of EC curve names to OpenSSL's internal numeric identifier ("NIDs").
# These numbers come from OpenSSL in crypto/objects/obj_mac.num
#
# For curve name comparisons between SECG, NIST, and ANSI, see these docs:
# (TLS) https://tools.ietf.org/html/rfc4492#appendix-A
# (SSH) https://tools.ietf.org/html/rfc5656#section-10.2
#
# Revision: 1.4

global_var curve_nid = {};

curve_nid.nist = {};
curve_nid.nist.B163 = 723;
curve_nid.nist.B233 = 727;
curve_nid.nist.B283 = 730;
curve_nid.nist.B409 = 732;
curve_nid.nist.B571 = 734;
curve_nid.nist.K163 = 721;
curve_nid.nist.K233 = 726;
curve_nid.nist.K283 = 729;
curve_nid.nist.K409 = 731;
curve_nid.nist.K571 = 733;
curve_nid.nist.P192 = 409;
curve_nid.nist.P224 = 713;
curve_nid.nist.P256 = 415;
curve_nid.nist.P384 = 715;
curve_nid.nist.P521 = 716;

# From RFC 5480 section 2.1.1.1
# These are all NIST curves.
curve_nid.oid = {};
curve_nid.oid["1.2.840.10045.3.1.1"] = curve_nid.nist.P192;
curve_nid.oid["1.3.132.0.1"]  = curve_nid.nist.K163;
curve_nid.oid["1.3.132.0.15"] = curve_nid.nist.B163;
curve_nid.oid["1.3.132.0.33"] = curve_nid.nist.P224;
curve_nid.oid["1.3.132.0.26"] = curve_nid.nist.K233;
curve_nid.oid["1.3.132.0.27"] = curve_nid.nist.B233;
curve_nid.oid["1.2.840.10045.3.1.7"] = curve_nid.nist.P256;
curve_nid.oid["1.3.132.0.16"] = curve_nid.nist.K283;
curve_nid.oid["1.3.132.0.17"] = curve_nid.nist.B283;
curve_nid.oid["1.3.132.0.34"] = curve_nid.nist.P384;
curve_nid.oid["1.3.132.0.36"] = curve_nid.nist.K409;
curve_nid.oid["1.3.132.0.37"] = curve_nid.nist.B409;
curve_nid.oid["1.3.132.0.35"] = curve_nid.nist.P521;
curve_nid.oid["1.3.132.0.38"] = curve_nid.nist.K571;
curve_nid.oid["1.3.132.0.39"] = curve_nid.nist.B571;

# From:
#   http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
# "IANA TLS Parameters: Supported Groups Registry"
curve_nid.tls = {};
# '0' is unassigned
curve_nid.tls[1]  = curve_nid.nist.K163;
curve_nid.tls[2]  = 722;
curve_nid.tls[3]  = curve_nid.nist.B163;
curve_nid.tls[4]  = 724;
curve_nid.tls[5]  = 725;
curve_nid.tls[6]  = curve_nid.nist.K233;
curve_nid.tls[7]  = curve_nid.nist.B233;
curve_nid.tls[8]  = 728;
curve_nid.tls[9]  = curve_nid.nist.K283;
curve_nid.tls[10] = curve_nid.nist.B283;
curve_nid.tls[11] = curve_nid.nist.K409;
curve_nid.tls[12] = curve_nid.nist.B409;
curve_nid.tls[13] = curve_nid.nist.K571;
curve_nid.tls[14] = curve_nid.nist.B571;
curve_nid.tls[15] = 708;
curve_nid.tls[16] = 709;
curve_nid.tls[17] = 710;
curve_nid.tls[18] = 711;
curve_nid.tls[19] = curve_nid.nist.P192;
curve_nid.tls[20] = 712;
curve_nid.tls[21] = curve_nid.nist.P224;
curve_nid.tls[22] = 714;
curve_nid.tls[23] = curve_nid.nist.P256; # aka secp256r1 aka prime256v1
curve_nid.tls[24] = curve_nid.nist.P384; # aka secp384r1
curve_nid.tls[25] = curve_nid.nist.P521;
# we don't support these yet but here they are as reference
#curve_nid.tls[26] = 927; # brainpoolP256r1
#curve_nid.tls[27] = 931; # brainpoolP384r1
#curve_nid.tls[28] = 933; # brainpoolP512r1
#curve_nid.tls[29] = 1034; # x25519
#curve_nid.tls[30] = 1035; # x448
#curve_nid.tls[31] = 927; # brainpoolP256r1
#curve_nid.tls[32] = 931; # brainpoolP384r1
#curve_nid.tls[33] = 933; # brainpoolP512r1
# 34 to 41 are currently drafts and not present in openssl yet
# 42-255 are unassigned
#curve_nid.tls[256] = 1126; # ffdhe2048
#curve_nid.tls[257] = 1127; # ffdhe3072
#curve_nid.tls[258] = 1128; # ffdhe4096
#curve_nid.tls[259] = 1129; # ffdhe6144
#curve_nid.tls[260] = 1130; # ffdhe8192

function ecc_functions_available()
{
  if (defined_func("ecc_scalar_multiply") && defined_func("ecc_curve_details") && defined_func("bn_mod_inverse"))
    return TRUE;
  else
    return FALSE;
}

# Shift a bignum right by <bits> bits.
# Used only in ECDSA (generating 'z') when signing/verifying
function bn_rshift(bn, bits)
{
  return bn_div(bn, bn_exp(bn_dec2raw(string(2)), bn_dec2raw(string(bits))));
}

# Returns TRUE on successful verification or FALSE on failure
function ecdsa_verify(msg, x, y, r, s, hash, curve_nid)
{
  var point, curve_info, z, bits_to_drop, w, u1, u2;

  # Can't verify signatures if we're missing the builtins!
  if (!ecc_functions_available())
    return FALSE;

  curve_info = ecc_curve_details(curve_nid:curve_nid);
  if (isnull(curve_info))
    return FALSE;

  # Check that a public key is valid
  point = ecc_scalar_multiply(
    y:y,
    x:x,
    curve_nid:curve_nid,
    scalar:curve_info.order
  );
  if (!point.input_is_on_curve)
    return FALSE; # Point not on curve
  if (!point.result_is_at_infinity)
    return FALSE; # Point on curve, but is a "weak point"

  # Check that r and s are valid
  if (bn_cmp(key1:r, key2:curve_info.order) != -1 || bn_cmp(key1:r, key2:bn_dec2raw("0")) != 1)
    return FALSE; # r is out of range

  # Exact same check on 's' as the previous one for 'r'
  if (bn_cmp(key1:s, key2:curve_info.order) != -1 || bn_cmp(key1:s, key2:bn_dec2raw("0")) != 1)
    return FALSE; # s is out of range

  z = hash(msg);
  # Truncate Z if we need to (when the hash is bigger than the curve)
  if ((bits_to_drop = (strlen(z) * 8) - curve_info.order_bits) > 0)
    z = bn_rshift(bn:z, bits:bits_to_drop);

  w = bn_mod_inverse(s, curve_info.order);
  if (isnull(w))
    return FALSE;

  u1 = bn_mod_mul(z, w, curve_info.order);
  u2 = bn_mod_mul(r, w, curve_info.order);

  point = ecc_scalar_multiply(
    y:y,
    x:x,
    curve_nid:curve_nid,
    scalar:u2,
    g_scalar:u1
  );

  if (bn_cmp(key1:r, key2:bn_mod(point.x, curve_info.order)) != 0)
    return FALSE;

  return TRUE;
}

# This follows the procedure in SECG's SEC1v2 section 3.2.1
# This is appropriate for generating an ECDHE private key and for
# generating the per-signature 'k' when signing with ECDSA.
function ecc_generate_secret_key(curve_nid)
{
  local_var i, bits_to_generate, bytes, key, curve_info;

  curve_info = ecc_curve_details(curve_nid:curve_nid);
  bits_to_generate = strlen(curve_info.order) * 8;

  # 2**16 attempts picked for:
  # * Roughly 0.5 seconds of attempts before terminating
  # * Will never fail in practice, probability-wise
  for (i = 0; i < 2**16; ++i)
  {
    # Randomly generate a sequence of bytes
    # Check if, when treated as a bignum, it falls in the allowed range
    # for a secret key for this particular curve.
    key = random(need:bits_to_generate);
    # Greater than 0 and less than the order.
    if (bn_cmp(key1:key, key2:curve_info.order) == -1 && bn_cmp(key1:key, key2:bn_dec2raw("0")) == 1)
      return key;
  }

  # Bail. We can't safely generate a key and we can't require
  # plugin writers to handle this correctly. Negligible probability
  # of this ever happening... ever.
  exit(1, "Failed to generate an ECC secret key in " + i + " attempts");
}

##
# This should be replaced with the "degree" field from the ecc_curve_details
# builtin.
##
function _internal_ecc_curve_field_element_size(curve_nid)
{
  local_var nid_to_field_element_size;
  nid_to_field_element_size = {
    "409": 192,
    "415": 256,
    "708": 160,
    "709": 160,
    "710": 160,
    "711": 192,
    "712": 224,
    "713": 224,
    "714": 256,
    "715": 384,
    "716": 528,
    "721": 168,
    "722": 168,
    "723": 168,
    "724": 200,
    "725": 200,
    "726": 240,
    "727": 240,
    "728": 240,
    "729": 288,
    "730": 288,
    "731": 416,
    "732": 416,
    "733": 576,
    "734": 576
  };

  return nid_to_field_element_size[string(curve_nid)];
}

# FE2OSP: converts a single coordinate (x, or y) to a byte string that is a
# consistent maximum length. This is used when encoding a public key into an
# 'uncompressed' ('type 4') encoding in SSL and SSH.
# This is also used in SSL to encode the X coordinate from the shared
# secret, before it's derived into MAC and encryption keys.
function ecc_fe2osp(curve_nid, element)
{
  local_var field_element_size;
  # Typically this would be provided by the curve_info.degree hash field
  field_element_size = _internal_ecc_curve_field_element_size(curve_nid:curve_nid) / 8;
  return crap(data:'\x00', length:field_element_size - strlen(element)) + element;
}
