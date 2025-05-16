#TRUSTED 46c1746e27fc98a0b87abfbe17e3b236160225f00e6a75a3959baf5189a6530d148bf6609c3d56b416e98a750ccdd068f44989f4912ba3192e1c0ef4bd0bd0033fd094490c2e61b3a4aae83ac1150935f2dad827b599e81c6baf5eb56ad955ad2dae4bea90fbdafbff5ae0e7e3bc90cdc293090bb6890e1a7847d073e124b934922061c03e2d04180545c89b58d5f21dedeaefa268f53eb60e1ba7c895a3501f183a8ac15f01f9fd2589ff1ca3703e131f3a2199c8d9c831341e62a081f5e2ab3fb47a82bd1cae23966c8478de72cebf17d05ec71463580757c963093d0df2abde1340a8b30abab24438775855556abf88d411c6fbaaf0ee3a6913c90996f3571d52b068443097be8f274fbbd20f5229ae6ed31069fbe2453dc0a238d9ea8eb4017d7a2b0f7f50d433eaa76de38b304256aaf13b6caf12e3d52c05edf42d04c1aed9f3c751622c696d4b6169af84fe5f6bd7d9be0f97362a5d82d0dd88f08765b435b0f12ad37376767e70d21e1c280e30b5c68a8b53a9eacfcb3e4fda7182f7107bcaa330d877d3081018c58f6437b205c5f92c87050de1fe8d8f582e0fcdfb81290335cfc824deda0a932928a14ffdf66dfce6a88f0de019cf6c60040f5906d7fca0089753bcb3e107fe093a718e1e963b056e872952b98cba0a55a263c19d25efd68067042897eb923ab335010c1710fd8a8dd0250f4ea5d85fc839fec33c
#TRUST-RSA-SHA256 6fa91040347a21f6efea114b2674ea87f31f1ebf76562023ecbfcbe3d7ab9b99db12a39903f920142d927a5c1b2f42162e0b6b791fa910011ee8eea83af9e4f4bb47dd97b002d3bedd59aef9b355dce5037e89ad04620fe25ef2787589bf781b3f5ffaf8f2fbd80d2311598998efa4238f8d90b6c528cfd89445800f2d5c02b997d127594d5dc6c62153d11b6df96fa11abd2f16e75798066f1345b7a0983c05a1605c53183cc7d798a6d80627376c6d4d3f82786fafbab273dee2127e7febf87f1bea9e44777092e1d5f7527dc188e2225e5e42b2d68fe1dbe76d694b3079df3c8d72d8f888c39751d74439c91939500181804a11b6690704dd7173d9998d3e36c8d0dbdcdd162cd1e7a2f97f5da5fa43e385a3e9b60562c269b3af24022d506b6316869dbefd92acea64675d1afec99d5defb3d767595ef25b82442a14eb19e396d6f623a5b6ee94d05e9ac5c5f6a250c9f9503f0f974062fc0c272511b1a12749eb0bce2733eaf602bc14a13fcf85b7d93c5c9371d30bf778f999017207ce7565d72495b014e87f535bba9076de4b35269c726121f7df6432eb17d129b8563024d6de4ab9ed8ff2482eccba22ad6f5425a57335eb29566ae3add79bfdac9203f4f1e61acadde7188f6df9a3b13f32c074eabbf6bdbb10dfcd248b64255509e4b4fcb7630e5df552dc5a14825a69f44c90351500a11202a74f1182befaaedf
#------------------------------------------------------------------------------
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.3
###

include("compat_shared.inc");
include("debug.inc");
include("der_funcs.inc");
include("crypto_func.inc");
include("base64.inc");
include("stream_func.inc");
include("x509_func.inc");

##
#
# Namespace pkcs12
#   Encapsulates naming for PKCS#12 related functions and variables
##
namespace pkcs12
{
  #PKCS1 Appendix A - https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1
  global_var PKCS1_RSA_ENCRYPTION              = "1.2.840.113549.1.1.1";

  #PKCS9 Appendix A - https://datatracker.ietf.org/doc/html/rfc2985#appendix-A
  global_var PKCS9_FRIENDLY_NAME               = "1.2.840.113549.1.9.20";
  global_var PKCS9_LOCAL_KEY_ID                = "1.2.840.113549.1.9.21";

  #PKCS12 4.1 - https://datatracker.ietf.org/doc/html/rfc7292#section-4.1
  global_var PKCS7_DATA_OID                    = "1.2.840.113549.1.7.1";
  global_var PKCS7_ENVELOPEDDATA_OID           = "1.2.840.113549.1.7.3";
  global_var PKCS7_ENCRYPTEDDATA_OID           = "1.2.840.113549.1.7.6";

  #PKCS12 Appendix C - https://datatracker.ietf.org/doc/html/rfc7292#appendix-C
  global_var PKCS12_PBE_SHA1_128RC4_OID        = "1.2.840.113549.1.12.1.1";
  global_var PKCS12_PBE_SHA1_40RC4_OID         = "1.2.840.113549.1.12.1.2";
  global_var PKCS12_PBE_SHA1_3KEY_3DES_CBC_OID = "1.2.840.113549.1.12.1.3";
  global_var PKCS12_PBE_SHA1_2KEY_3DES_CBC_OID = "1.2.840.113549.1.12.1.4";
  global_var PKCS12_PBE_SHA1_128RC2_CBC_OID    = "1.2.840.113549.1.12.1.5";
  global_var PKCS12_PBE_SHA1_40RC2_CBC_OID     = "1.2.840.113549.1.12.1.6";

  #Each array element is a list of:
  #  Hash algorithm,
  #  Hash result length in bytes,
  #  Key length,
  #  IV length, and
  #  Encryption/decryption block size
  global_var PKCS12_KDF_PARAMS = {
    "1.2.840.113549.1.12.1.1" : [@SHA1, 20, 16, 0, 64],
    "1.2.840.113549.1.12.1.2" : [@SHA1, 20, 5, 0, 64],
    "1.2.840.113549.1.12.1.3" : [@SHA1, 20, 24, 8, 64],
    "1.2.840.113549.1.12.1.4" : [@SHA1, 20, 24, 8, 64],
    "1.2.840.113549.1.12.1.5" : [@SHA1, 20, 16, 8, 64],
    "1.2.840.113549.1.12.1.6" : [@SHA1, 20, 5, 8, 64],
  };

  #PKCS12 4.2 - https://datatracker.ietf.org/doc/html/rfc7292#section-4.2
  global_var PKCS12_KEY_BAG                   = "1.2.840.113549.1.12.10.1.1";
  global_var PKCS12_PKCS8_SHROUDED_KEY_BAG    = "1.2.840.113549.1.12.10.1.2";
  global_var PKCS12_CERT_BAG                  = "1.2.840.113549.1.12.10.1.3";
  global_var PKCS12_CRL_BAG                   = "1.2.840.113549.1.12.10.1.4";
  global_var PKCS12_SECRET_BAG                = "1.2.840.113549.1.12.10.1.5";
  global_var PKCS12_SAFE_CONTENTS_BAG         = "1.2.840.113549.1.12.10.1.6";

  #PKCS-12 KDF types - Appedix B - https://datatracker.ietf.org/doc/html/rfc7292#appendix-B.3
  global_var PKCS12_KEY_ID = 1;
  global_var PKCS12_IV_ID  = 2;
  global_var PKCS12_MAC_ID = 3;

  ##
  # Derives cryptographic material from a passphrase for PKCS12 containers.
  # Can be used to derive an encryption key, IV or MAC key depending on the
  # value of the type parameter.
  #
  # @param [hash:function]   Pointer to a hashing algorithm @MD5, @SHA256, etc.
  # @param [hashLen:integer] Length of the digest computed by the hash parameter.
  # @param [type:integer]    What to derive: 1=key, 2=IV, 3=MAC key
  # @param [blksz:integer]   Blocksize of the hash algorithm.
  # @param [password:bytes]  Password BMP unicode string (code page first)
  # @param [iter:integer]    Iterations of rehashing used to derive result.
  # @param [salt:bytes]      A salt value added to prevent dictionary attacks.
  # @param [size:integer]    Size in bytes of the desired result.
  #
  # @return Returns a value to be used in encrypting, decrypting or validating a
  #         PKCS12 container.
  ##
  function pkcs12_kdf_helper(hash, hashLen, type, blksz, password, iter, salt, size)
  {
    var passLen = strlen(password);
    var saltLen = strlen(salt);
    var initial = crap(data:raw_string(type), blksz);
    var pSize = blksz * ((passLen + blksz - 1) / blksz);
    var sSize = blksz * ((saltLen + blksz - 1) / blksz);

    if(empty_or_null(password))
    {
      passLen = 0;
      pSize = 0;
    }

    if(isnull(hashLen) || hashLen == 0)
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Bad input, missing hash length.");
      return NULL;
    }

    for(var i = 0; i < sSize; i++)
      initial += salt[i % saltLen];

    for(i = 0; i < pSize; i++)
      initial += password[i % passLen];

    var result = '';
    var n = size;
    var hashBytes, tmpBytes;

    while(n > 0)
    {
      hashBytes = initial;

      for(i = 0; i < iter; i++)
        hashBytes = hash(hashBytes);

      result += hashBytes;
      tmpBytes = '';

      for(i = 0; i < blksz; i++)
        tmpBytes += hashBytes[i % hashLen];

      for(i = blksz; i < blksz + pSize + sSize; i += blksz)
      {
        var c = 1;
        for(var j = blksz - 1; j >= 0; j--)
        {
          c += ord(initial[i + j]) + ord(tmpBytes[j]);
          initial[i + j] = raw_string(c & 0xff);
          c >>= 8;
        }
      }

      n -= hashLen;
    }

    if(strlen(result) < size)
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "KDF produced too few bytes.");
      return NULL;
    }

    return substr(result, 0, size - 1);
  }

  ##
  # Derives a key and IV from a password for decrypting or encrypting
  # a collection of PKCS12 safe bags.  The algorithm for this KDF is
  # described in Appendix B of the IETF PKCS#2 standard:
  #   https://datatracker.ietf.org/doc/html/rfc7292#appendix-B
  #
  # @param [algo:string]    OID for the encryption algorithm used.
  # @param [password:bytes] Password BMP unicode string (code page first)
  # @param [iter:integer]   Iterations of rehashing used to derive result.
  # @param [salt:bytes]     A salt value added to prevent dictionary attacks.
  #
  # @return Returns an array of [key, IV] which can be used to encrypt or
  #         decrypt the safe bags collection of a PKCS12 container.
  #         Or NULL if an error occurred.
  ##
  function pkcs12_password_kdf(algo, password, iter, salt)
  {
    if(isnull(algo) || !iter || isnull(salt))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing parameters.");
      return NULL;
    }

    var kdf_params = PKCS12_KDF_PARAMS[algo];
    if(isnull(kdf_params))
    {
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Unknown algorithm",
        msg_details: {
          "algo": {"lvl": 1, "value": serialize(algo)}});
      return NULL;
    }

    var hashAlgo = kdf_params[0];
    var hashLen = kdf_params[1];
    var keyLength = kdf_params[2];
    var ivLength = kdf_params[3];
    var blockSize = kdf_params[4];

    if(!isnull(password))
      password = raw_string('\x00') + mk_unicode_or_null(password) + raw_string('\x00');

    var key = pkcs12_kdf_helper(hash:hashAlgo, hashLen:hashLen, type:PKCS12_KEY_ID, blksz:blockSize,
                                password:password, iter:iter, salt:salt, size:keyLength);

    if(isnull(key))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Error deriving key.");
      return NULL;
    }

    var iv = NULL;
    if(ivLength > 0)
    {
      iv = pkcs12_kdf_helper(hash:hashAlgo, hashLen:hashLen, type:PKCS12_IV_ID, blksz: blockSize,
                             password:password, iter:iter, salt:salt, size:ivLength);

      if(isnull(iv))
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Error deriving IV.");
        return NULL;
      }
    }

    return [key, iv];
  }

  ##
  # PEM encodes a DER encoded unencrypted private key
  #
  # @param [keyBytes:bytes] DER encoded private key
  # @param [tag:string]     PEM header and footer text.
  #
  # @return [string] Returns PEM encoded private key
  ##
  function PEM_encode_blob(keyBytes, tag)
  {
    var b64 = base64encode(str: keyBytes);
    var b64Length = strlen(b64);
    var end;

    var pemKey = '-----BEGIN ' + tag + '-----\n';
    for(var i = 0; i < b64Length; i += 64)
    {
      end = i + 64;
      if(end > b64Length)
        end = b64Length;
      pemKey += substr(b64, i, end - 1) + '\n';
    }
    pemKey += '-----END ' + tag + '-----\n';
    return pemKey;
  }

  ##
  # Decodes a DER encoded PKCS8 shrouded key bag.
  #
  # @param [bag:bytes]       DER encoded keyBag.
  # @param [password:string] The PKCS12 container passphrase
  #
  # @return Returns an array containing the PEM encoded key and
  #         key metadata. Or NULL if an error occurred.
  ##
  function decode_shrouded_key_bag(bag, password)
  {
    var bagContentsDecoded = der_parse_sequence(seq:bag, list:TRUE);
    if(isnull(bagContentsDecoded))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode bag contents.");
      return NULL;
    }

    var encryptedBag = der_parse_octet_string(string:bagContentsDecoded[2]);

    var bagOIDSequence = der_parse_sequence(seq:bagContentsDecoded[1], list:TRUE);
    if(isnull(bagOIDSequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode bag OID.");
      return NULL;
    }

    var bagOID = der_parse_oid(oid:bagOIDSequence[1]);
    var metaSequence = der_parse_sequence(seq:bagOIDSequence[2], list:TRUE);
    if(isnull(metaSequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode shrouded bag metadata.");
      return NULL;
    }

    var salt = der_parse_octet_string(string:metaSequence[1]);

    var iterations = der_parse_int(i:metaSequence[2]);
    var cipherKeys = pkcs12_password_kdf(algo:bagOID,
                           password:password,
                           iter:iterations,
                           salt:salt);

    if(isnull(cipherKeys))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to generate a key and or IV from the password.");
      return NULL;
    }

    var key = cipherKeys[0];
    var IV = cipherKeys[1];

    var decryptedData = tripledes_cbc_decrypt(data:encryptedBag, key:key, iv:IV);

    return decode_key_bag(bag:decryptedData[0]);
  }


  ##
  # Decodes a DER encoded PKCS12 key bag.
  #
  # @param [bag:bytes] DER encoded keyBag.
  #
  # @return Returns an array containing the PEM encoded key and
  #         key metadata. Or NULL if an error occurred.
  ##
  function decode_key_bag(bag)
  {
    var bagContentsDecoded = der_parse_sequence(seq:bag, list:TRUE);
    if(isnull(bagContentsDecoded))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode bag contents.");
      return NULL;
    }

    var bagVersion = der_parse_int(i:bagContentsDecoded[1]);

    var bagOIDSequence = der_parse_sequence(seq:bagContentsDecoded[2], list:TRUE);
    if(isnull(bagOIDSequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode bag OID.");
      return NULL;
    }

    var bagOID = der_parse_oid(oid:bagOIDSequence[1]);

    #TODO - add support for ECDSA keys
    if(bagOID == PKCS1_RSA_ENCRYPTION)
    {
      var pemKey = PEM_encode_blob(keyBytes:bag, tag:"RSA PRIVATE KEY");
    }
    else
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Key type not supported.");
      return NULL;
    }

    return {"version":bagVersion, "type":bagOID, "private_key":pemKey};
  }

  ##
  # Decodes a DER encoded PKCS12 certificate bag.
  #
  # @param [bag:bytes] DER encoded certBag.
  #
  # @return Returns an array containing the PEM encoded certificate
  #         and certificate metadata. Or NULL if an error occurred.
  ##
  function decode_cert_bag(bag)
  {
    var bagContentsDecoded = der_parse_sequence(seq:bag, list:TRUE);
    if(isnull(bagContentsDecoded))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode cert bag contents.");
      return NULL;
    }

    var bagDataOID = der_parse_oid(oid:bagContentsDecoded[1]);

    var bagDataContents = der_decode(data:bagContentsDecoded[2]);
    var bagDataSequence = der_parse_octet_string(string: bagDataContents[1]);
    var bagDataSequenceDecoded = der_parse_sequence(seq:bagDataSequence, list:TRUE);
    if(isnull(bagDataSequenceDecoded))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode cert bag data sequence.");
      return NULL;
    }

    var certificateValues = parse_der_cert(cert:bagDataSequence);
    var subject = certificateValues["tbsCertificate"]["subject"];
    var issuer = certificateValues["tbsCertificate"]["issuer"];
    var certificate = PEM_encode_blob(keyBytes:bagDataSequence, tag:"CERTIFICATE");

    return {"type": bagDataOID, "certificate": certificate, "subject":subject, "issuer":issuer};
  }

  ##
  # Partially decodes a DER encoded PKCS12 bag with a type
  # that is not currently supported by this library
  #
  # @param [bag:bytes] DER encoded safeBag.
  #
  # @return Returns an array containing bag metadata and
  #         still encoded parts of the bag. Or NULL if an error occurred.
  ##
  function decode_unknown_bag(bag)
  {
    var bagContentsDecoded = der_parse_sequence(seq:bag, list:TRUE);
    if(isnull(bagContentsDecoded))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode unknown bag contents.");
      return NULL;
    }

    var bagDataOID = der_parse_oid(oid:bagContentsDecoded[1]);

    var bagDataContents = der_decode(data:bagContentsDecoded[2]);
    var bagDataSequence = der_parse_octet_string(string: bagDataContents[1]);
    var bagDataSequenceDecoded = der_parse_sequence(seq:bagDataSequence, list:TRUE);

    if(isnull(bagDataSequenceDecoded))
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode unknown bag data sequence.");
    return {"type": bagDataOID, "data": bagDataSequenceDecoded};
  }

  ##
  # Decodes a DER encoded PKCS12 safe bag metadata collection.
  #
  # @param [metadata:bytes] DER encoded metadata collection.
  #
  # @return Returns an array of decoded metadata items.
  #         Or NULL if an error occurred.
  ##
  function decode_bag_metadata(metadata)
  {
    var result;
    var bagMetadataSequence = der_parse_set(set:metadata, list:TRUE);
    if(isnull(bagMetadataSequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode bag metadata.");
      return NULL;
    }

    for(var i = 0; i < bagMetadataSequence[0]; i++)
    {
      var bagMetadataItemSequence = der_parse_sequence(seq:bagMetadataSequence[i + 1], list:TRUE);
      if(isnull(bagMetadataItemSequence))
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode bag metadata item.");
        continue;
      }

      var OID = der_parse_oid(oid: bagMetadataItemSequence[1]);
      var stringSet = der_parse_set(set:bagMetadataItemSequence[2], list:TRUE);
      if(isnull(stringSet))
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode bag metadata string set.");
        continue;
      }

      var metaItem = {"type":OID};

      if(OID == PKCS9_FRIENDLY_NAME)
      {
        var berName = der_parse_bmp_string(bmpString:stringSet[1]);
        var friendlyName;
        if(!isnull(berName))
        {
          berName = substr(berName, 1, strlen(berName) - 1) + '\x00';
          friendlyName = unicode_to_ascii(berName);
        }

        metaItem["friendly_name"] = friendlyName;
      }
      else if(OID == PKCS9_LOCAL_KEY_ID)
      {
        var local_key_id = der_parse_octet_string(string:stringSet[1]);
        metaItem["local_key_id"] = hexstr(local_key_id);
      }
      else
      {
        dbg::detailed_log(
          lvl: 2,
          src: FUNCTION_NAME,
          msg: "Unknown metadata",
          msg_details: {
            "OIS": {"lvl": 3, "value": OID},
            "Data": {"lvl": 3, "value": bagMetadataItemSequence[2]}});
        continue;
      }

      result[i] = metaItem;
    }

    return result;
  }

  ##
  # Decodes a safe bag from a collection of PKCS12 safe bags.
  #
  # @param [bag:bytes]       DER encoded safeBag.
  # @param [password:string] The PKCS12 container passphrase
  #
  # @return Returns an array containing the contents of the safe
  #         bag and its metadata. Or NULL if an error occurred.
  ##
  function decode_safe_bag(bag, password)
  {
    var decodedBag = der_parse_sequence(seq:bag, list:TRUE);
    if(isnull(decodedBag))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Could not decode bag.");
      return NULL;
    }

    var bagOID = der_parse_oid(oid:decodedBag[1]);
    var result = {"type":bagOID};
    var bagContents = der_decode(data:decodedBag[2]);

    if(bagOID == PKCS12_KEY_BAG)
      result["bag"] = decode_key_bag(bag:bagContents[1]);
    else if(bagOID == PKCS12_CERT_BAG)
      result["bag"] = decode_cert_bag(bag:bagContents[1]);
    else if(bagOID == PKCS12_PKCS8_SHROUDED_KEY_BAG)
      result["bag"] = decode_shrouded_key_bag(bag:bagContents[1], password:password);
    else
      result["bag"] = decode_unknown_bag(bag:bagContents[1]);

    result["metadata"] = decode_bag_metadata(metadata:decodedBag[3]);

    return result;
  }

  ##
  # Decode an unencrypted PKCS12 ContentInfo sequence.
  #
  # @param [contentInfo:bytes] DER encoded ContentInfo sequence.
  # @param [password:string] The PKCS12 container passphrase
  #
  # @return Returns a list of decoded content info contents.
  #         Or NULL if an error occurred.
  ##
  function decode_content_info(contentInfo, password)
  {
    var result;
    var decryptedBagSequence = der_parse_sequence(seq: contentInfo, list:TRUE);
    if(isnull(decryptedBagSequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to decode content info sequence. Bad password?");
      return NULL;
    }

    var decryptedBagItemCount = decryptedBagSequence[0];
    for(var i = 0; i < decryptedBagItemCount; i++)
      result[i] = decode_safe_bag(bag:decryptedBagSequence[i + 1], password:password);

    return result;
  }

  ##
  # Decodes an unencrypted PKCS12 authenticated safe data element.
  #
  # @param [data:bytes] DER encoded unencrypted data element.
  # @param [password:string] The PKCS12 container passphrase
  #
  # @return Returns an array of decoded PKCS12 auth data.
  #         Or NULL if an error occurred.
  ##
  function decode_data(data, password)
  {
    var subsequenceOctets = der_parse_octet_string(string:data);

    var pkcs7Subsequence = der_parse_sequence(seq:subsequenceOctets, list:TRUE);

    if(isnull(pkcs7Subsequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to parse pkcs7 data subsequence.");
      return NULL;
    }

    var result = decode_safe_bag(bag:pkcs7Subsequence[1], password:password);

    return {"data": result};
  }

  ##
  # Decodes an encrypted a PKCS12 authenticated safe data element.
  #
  # @param [data:bytes]      DER encoded encrypted data element.
  # @param [password:string] Password protecting the PKCS12 container.
  #
  # @return Returns an array of decoded PKCS12 auth data.
  #         Or NULL if an error occurred.
  ##
  function decode_encrypted_data(data, password)
  {
    var encryptedDataSequence = der_parse_sequence(seq:data, list:TRUE);
    if(isnull(encryptedDataSequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to parse encryptedData sequence.");
      return NULL;
    }

    var result = {"version": der_parse_int(i:encryptedDataSequence[1])};

    var encryptedDataSubsequence = der_parse_sequence(seq:encryptedDataSequence[2], list:TRUE);
    if(isnull(encryptedDataSubsequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to parse encryptedData subsequence.");
      return NULL;
    }

    if(encryptedDataSubsequence[0] != 3)
    {
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Encrypted data subsequence has the wrong number of elements.",
        msg_details:{
        "Data": {"lvl":3, "value": encryptedDataSubsequence}});
      return NULL;
    }

    var encryptedDataTypeOID = der_parse_oid(oid:encryptedDataSubsequence[1]);
    var encryptedDataTypeSequence = der_parse_sequence(seq:encryptedDataSubsequence[2], list:TRUE);
    var encryptedDataAuthData = der_parse_data(tag:BER_AUTHENTICATION_TAG, data:encryptedDataSubsequence[3]);

    if(isnull(encryptedDataTypeOID) || isnull(encryptedDataTypeSequence) || isnull(encryptedDataAuthData))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to decode encrypted data.");
      return NULL;
    }

    result["type"] = encryptedDataTypeOID;
    var decodedEncryptedDataTypeOID = der_parse_oid(oid:encryptedDataTypeSequence[1]);
    result["encryptAlgo"] = decodedEncryptedDataTypeOID;
    var decodedPBEParamsSequence = der_parse_sequence(seq:encryptedDataTypeSequence[2], list:TRUE);

    if(isnull(decodedEncryptedDataTypeOID) || isnull(decodedPBEParamsSequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to decode PBE params.");
      return NULL;
    }

    var pbeSalt = der_parse_octet_string(string:decodedPBEParamsSequence[1]);
    var pbeIterations = der_parse_int(i:decodedPBEParamsSequence[2]);

    var cipherKeys = pkcs12_password_kdf(algo:decodedEncryptedDataTypeOID,
                           password:password,
                           iter:pbeIterations,
                           salt:pbeSalt);

    if(isnull(cipherKeys))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: ": Failed to generate a key and or IV from the password.");
      return NULL;
    }

    var key = cipherKeys[0];
    var IV = cipherKeys[1];
    var decryptedData = NULL;

    if(decodedEncryptedDataTypeOID == PKCS12_PBE_SHA1_3KEY_3DES_CBC_OID ||
       decodedEncryptedDataTypeOID == PKCS12_PBE_SHA1_2KEY_3DES_CBC_OID)
    {
      decryptedData = tripledes_cbc_decrypt(data:encryptedDataAuthData, key:key, iv:IV);
    }
    else if(decodedEncryptedDataTypeOID == PKCS12_PBE_SHA1_128RC2_CBC_OID ||
            decodedEncryptedDataTypeOID == PKCS12_PBE_SHA1_40RC2_CBC_OID)
    {
      decryptedData = decrypt_rc2_cbc(ciphertext:encryptedDataAuthData, key:key, iv:IV);
    }
    else
    {
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Unsupported container encryption algorithm",
        msg_details:{
          "Data": {"lvl":3, "value":decodedEncryptedDataTypeOID}});
      return NULL;
    }

    if(isnull(decryptedData) || isnull(decryptedData[0]))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to decrypt PKCS12 container. Bad password?");
      return NULL;
    }

    var decodedDecryptedData = decode_content_info(contentInfo:decryptedData[0], password:password);

    result["data"] = decodedDecryptedData;
    return result;
  }

  ##
  # Decodes a DER encoded PKCS12 AuthenticatedSafe structure.
  #
  # @param [safe:bytes]      DER encoded AuthenticatedSafe.
  # @param [password:string] Password protecting the PKCS12 container.
  # @param [macData:bytes]   DER encoded data used to validate container integrity.
  #
  # @return Returns an array of the information stored in the safe.
  #         Or NULL if an error occurred.
  ##
  function decode_auth_safe(safe, macData, password)
  {
    var result;

    #parse authSafe
    var authSafeDecoded = der_parse_sequence(seq:safe, list:TRUE);
    if(isnull(authSafeDecoded))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to decode authentication safe.");
      return NULL;
    }

    var authSafeOID = der_parse_oid(oid:authSafeDecoded[1]);
    var contentInfo = der_decode(data:authSafeDecoded[2]);
    contentInfo = der_parse_octet_string(string:contentInfo[1]);
    if(!isnull(macData))
    {
      var validated = validate_container(macData:macData, password:password, pfx:contentInfo);
      if(!validated)
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Wallet failed integrity check! Bad password?");
        return NULL;
      }
      if(validated == 2)
        password = NULL;
    }

    var contentInfoDecoded = der_parse_sequence(seq:contentInfo, list:TRUE);

    for(var i = 0; i < contentInfoDecoded[0]; i++)
    {
      var subseq = der_parse_sequence(seq:contentInfoDecoded[i + 1], list:TRUE);
      if(isnull(subseq))
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to decode subsequence.");
        continue;
      }

      var subsequenceOID = der_parse_oid(oid:subseq[1]);

      var subsequenceDecoded = der_decode(data:subseq[2]);
      if(isnull(subsequenceDecoded))
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to decode subsequence data.");
        continue;
      }

      var contentData;
      if(subsequenceOID == PKCS7_DATA_OID)
      {
        contentData = decode_data(data:subsequenceDecoded[1], password:password);
      }
      else if(subsequenceOID == PKCS7_ENCRYPTEDDATA_OID)
      {
        contentData = decode_encrypted_data(data:subsequenceDecoded[1], password:password);
      }
      else
      {
        dbg::detailed_log(
          lvl: 1,
          src: FUNCTION_NAME,
          msg: "Unknown subsequence OID....skipping.",
          msg_details:{
            "Data": {"lvl":3, "value":subsequenceDecoded[1]}});
        continue;
      }

      var contentInfoResult = {"content_data_type": subsequenceOID, "content_data":contentData};
      result[i] = contentInfoResult;
    }

    return result;
  }

  ##
  # Validates the wallet's PFX container using the wallet's MAC data.
  #
  # @param [macData:bytes]   DER encoded PKCS12 MAC data.
  # @param [password:string] The password protecting the container.
  # @param [pfx:bytes]       The container to validate.
  # @param [fixPass:boolean] If TRUE then fix empty passwords by setting them to NULL.
  #
  # @return Returns FALSE if validation, TRUE on success,
  #         2 if the password should be converted to NULL.
  ##
  function validate_container(macData, password, pfx, fixPass)
  {
    if(isnull(fixPass))
      fixPass = FALSE;

    var macDataDecoded = der_parse_sequence(seq: macData, list:TRUE);
    if(isnull(macDataDecoded) || macDataDecoded[0] < 2)
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Error decoding MAC data.");
      return FALSE;
    }

    var digestInfo = der_parse_sequence(seq: macDataDecoded[1], list:TRUE);
    var salt = der_parse_octet_string(string:macDataDecoded[2]);
    var iterations = 1;
    if(macDataDecoded[0] > 2)
      iterations = der_parse_int(i:macDataDecoded[3]);

    if(isnull(digestInfo))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Error decoding MAC digest sequence.");
      return FALSE;
    }

    var digestSequence = der_parse_sequence(seq:digestInfo[1], list:TRUE);
    if(isnull(digestSequence))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Error decoding MAC digest algo.");
      return FALSE;
    }

    var digest = der_parse_octet_string(string:digestInfo[2]);
    var digestAlgoOID = der_parse_oid(oid:digestSequence[1]);

    var blockSize = 0;
    var hashLen = 0;
    var hashAlgo = NULL;
    var hmacAlgo = NULL;
    var uniPass = NULL;

    if(!fixPass || !empty_or_null(password))
      uniPass = raw_string('\x00') + mk_unicode_or_null(password) + raw_string('\x00');

    #SHA1
    if(digestAlgoOID == "1.3.14.3.2.26")
    {
      hashAlgo = @SHA1;
      hmacAlgo = @HMAC_SHA1;
      hashLen = 20;
      blockSize = 64;
    }

    var key = pkcs12_kdf_helper(hash:hashAlgo, hashLen:hashLen, type:PKCS12_MAC_ID, blksz:blockSize,
                                password:uniPass, iter:iterations, salt:salt, size:hashLen);

    if(empty_or_null(key))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to generate HMAC verification key.");
      return FALSE;
    }

    var hmac = hmacAlgo(key:key, data:pfx);

    if(hmac == digest)
    {
      return TRUE;
    }
    #Empty passwords are handled differently across PCKS12 implementations.
    else if(!fixPass && empty_or_null(password))
    {
      var result = validate_container(macData:macData, password:password, pfx:pfx, fixPass:TRUE);
      if(result)
        return 2;
    }

    return FALSE;
  }

  ##
  # Parses a PKCS12 container.
  #
  # @param [container:bytes] A DER encoded PKCS12 container.
  # @param [password:string] The password protecting the container.
  #
  # @return Returns an array of the data stored in the container.
  #         Or NULL if an error occurred.
  ##
  function parse_pkcs12(container, password)
  {
    #parse PFX
    var mainPfx = der_parse_sequence(seq:container, list:TRUE);
    if(isnull(mainPfx))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to decode PFX container.");
      return NULL;
    }

    var count = mainPfx[0];
    var version = der_parse_int(i:mainPfx[1]);
    var authSafe = mainPfx[2];
    var macData;

    if(count > 2)
      macData = mainPfx[3];
    else
      macData = NULL;

    #Decode authentication safe
    var safe = decode_auth_safe(safe:authSafe, macData:macData, password:password);

    return {"version":version, "auth_safe":safe};
  }

  ##
  # This function parses decoded PKCS12 safebag data and
  # returns all of the stored private keys.
  #
  # @param [pkcs12Data:array] A list of PKCS12 safebags.
  #
  # @return Returns an array of private key data stored in
  #         the safebags list.
  ##
  function get_private_keys_from_pkcs12_data(pkcs12Data)
  {
    var found_private_keys = NULL;
    foreach var bag(pkcs12Data)
    {
      if(!isnull(bag["type"]) &&
         (bag["type"] == PKCS12_KEY_BAG || bag["type"] == PKCS12_PKCS8_SHROUDED_KEY_BAG))
      {
        if(isnull(found_private_keys))
          found_private_keys = [];

        append_element(var:found_private_keys, value:bag);
      }
    }

    return found_private_keys;
  }

  ##
  # Takes an array of decoded PKCS12 safe bags and a
  # decoded private key bag and finds the client certificate
  # related to the private key by matching their bag metadata
  # "local_key_id" values.
  #
  # @param [pkcs12Data:array]   An array of PKCS12 safebags.
  # @param [privateKey:array]   Decoded private key bag data.
  #
  # @return Returns decoded data for the first associated client
  #         certificate found based on matching local_key_id
  #         metadata. Or NULL if an error occurred.
  ##
  function get_related_client_cert(pkcs12Data, privateKey)
  {
    var found_client_cert = NULL;

    var pk_metadata = privateKey["metadata"];
    if(isnull(pk_metadata))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Private key bag has no metadata.");
      return NULL;
    }

    var pk_local_key_id = NULL;
    foreach var meta(pk_metadata)
    {
      if(!isnull(meta["type"]) && meta["type"] == PKCS9_LOCAL_KEY_ID)
      {
        pk_local_key_id = meta["local_key_id"];
        break;
      }
    }

    if(isnull(pk_local_key_id))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Can't find private keys local key id.");
      return NULL;
    }

    foreach var bag(pkcs12Data)
    {
      if(!isnull(bag["type"]) && bag["type"] == PKCS12_CERT_BAG)
      {
        var cert_metadata = bag["metadata"];
        if(isnull(cert_metadata))
          continue;

        foreach meta(cert_metadata)
        {
          if(!isnull(meta["type"]) && meta["type"] == PKCS9_LOCAL_KEY_ID && meta["local_key_id"] == pk_local_key_id)
            found_client_cert = bag;
        }

        if(!isnull(found_client_cert) && !isnull(found_client_cert['bag']))
          break;
      }
    }

    return found_client_cert['bag'];
  }

  ##
  # Takes an array of decoded PKCS12 safe bags and a
  # decoded client certificate bag and finds all parents
  # of that certificate in its chain of trust.
  #
  # @param [pkcs12Data:array]   An array of PKCS12 safebags.
  # @param [clientCert:array]   Decoded client cert bag data.
  #
  # @return Returns a string containing all PEM encoded certs in
  #         the client certificate's chain of trust.
  #         Or NULL if an error occurred.
  ##
  function get_related_chain_of_trust(pkcs12Data, clientCert)
  {
    var clientSubjectName, clientIssuerName;
    if(isnull(clientCert) || isnull(clientCert['subject']))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Client cert is missing a subject.");
      return NULL;
    }

    clientSubjectName = format_dn(clientCert['subject']);

    if(isnull(clientCert['issuer']))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Client cert is missing an issuer.");
      return NULL;
    }

    clientIssuerName = format_dn(clientCert['issuer']);

    #The certificate is self signed
    if(clientSubjectName == clientIssuerName)
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Client cert is self-signed.");
      return NULL;
    }

    var trustChain, subjectName, issuerName  = NULL;
    var certs = {}, trusts = {};

    foreach var bag(pkcs12Data)
    {
      if(!isnull(bag["type"]) && bag["type"] == PKCS12_CERT_BAG)
      {
        if(isnull(bag['bag']) || isnull(bag['bag']['subject']))
          continue;
        subjectName = format_dn(bag['bag']['subject']);

        if(isnull(bag['bag']) || isnull(bag['bag']['issuer']))
          continue;
        issuerName = format_dn(bag['bag']['issuer']);

        certs[subjectName] = bag["bag"];
        trusts[subjectName] = issuerName;
      }
    }

    var trustedCert = clientSubjectName;
    while(!isnull(certs[trustedCert]) && !isnull(trusts[trustedCert]) && trusts[trustedCert] != trustedCert)
    {
      if(isnull(certs[trustedCert]["certificate"]))
        return NULL;

      trustedCert = trusts[trustedCert];
      trustChain += certs[trustedCert]["certificate"] + '\n';
    }

    return trustChain;
  }
}

##
# Wrapper for ``pkcs12::parse_pkcs12()``.
#
# @remark See the documentation of ``pkcs12::parse_pkcs12()``.
##
function parse_pkcs12(container, password)
{
  return pkcs12::parse_pkcs12(container:container, password:password);
}

##
# Wrapper for ``pkcs12::get_private_keys_from_pkcs12_data()``.
#
# @remark See the documentation of ``pkcs12::get_private_keys_from_pkcs12_data()``.
##
function get_private_keys_from_pkcs12_data(pkcs12Data)
{
  return pkcs12::get_private_keys_from_pkcs12_data(pkcs12Data:pkcs12Data);
}

##
# Wrapper for ``pkcs12::get_related_client_cert()``.
#
# @remark See the documentation of ``pkcs12::get_related_client_cert()``.
##
function get_related_client_cert(pkcs12Data, privateKey)
{
  return pkcs12::get_related_client_cert(pkcs12Data:pkcs12Data, privateKey:privateKey);
}

##
# Wrapper for ``pkcs12::get_related_chain_of_trust()``.
#
# @remark See the documentation of ``pkcs12::get_related_chain_of_trust()``.
##
function get_related_chain_of_trust(pkcs12Data, clientCert)
{
  return pkcs12::get_related_chain_of_trust(pkcs12Data:pkcs12Data, clientCert:clientCert);
}

