#TRUSTED 994aed0817bead3d5f8c6847e5f545f9b3c0e5169e3ecc79f5a4cd158d5d4f745d52946c8ec3280089dc7c1037d41ab17d65588de386c5f20a7e8459c97e1c1e108036d8fc86c3ca992967c362ddb4a6b58f74ce6a02ea127720b192c1e065bcf240176ffd1501c8217843b55c4f8baef11828f5efcbe151fc86af61074b70a3f7b497636a9470c24b553524a1c01b18f992773eccb25d8469c8354eadc432738b6af01d7efe77fc4bd40e38fbc3d1475c40ad8a215edb0402ba71d3641beb40efc669820be5fe9b4b2aaa8f0b1213bbbb629a44b59e5f1b0a1d53f11b313c0014eceea748608294a593376b208e846851d886d4cf3da60a471a5e995ab7de37997347090bd8a5e9c32f9d72eb8b6b09662083d7ab021b68f7d029fe0c041ba0c455ac8c8b22c5e1b68e1022c2ddcbbff214c8cfd568583b1b4d6945369e859513f71e409312e4c00f94063cd4ec431549d2b00ea53a3f35a68b9268ce6e98aa77f6961e13f3a41ba8766bb5c64c78f529bc4ae8ca6cd5b728c6cafd9692e44b316229036869695a42c2d34f877001d829d8ff742538b95ab1ff24eb8259f2da3a65c5e9f1eb8e5d3556ab0113221e355b878851da8d55d9085075a1b9056c91b2994b945d4cf629de5db2ef6af000608bf43cb5aafbc85c5ffe3b443ff8391086d04d678097d095d756a32333f4fc72e4c78ee8359fbbf2f6ec811043bfed82

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.1
#


# ASN.1 tag values 
global_var V_ASN1_CONSTRUCTED            = (1<<5);
global_var ASN1_EOC                      = 0x00;
global_var ASN1_BOOLEAN                  = 0x01;
global_var ASN1_INTEGER                  = 0x02;
global_var ASN1_BIT_STRING               = 0x03;
global_var ASN1_OCTET_STRING             = 0x04;
global_var ASN1_NULL                     = 0x05;
global_var ASN1_OBJECT                   = 0x06;
global_var ASN1_OBJECT_DESCRIPTOR        = 0x07;
global_var ASN1_EXTERNAL                 = 0x08;
global_var ASN1_REAL                     = 0x09;
global_var ASN1_ENUMERATED               = 0x0a;
global_var ASN1_UTF8STRING               = 0x0c;
global_var ASN1_SEQUENCE                 = 0x10 | V_ASN1_CONSTRUCTED;
global_var ASN1_SET                      = 0x11 | V_ASN1_CONSTRUCTED;
global_var ASN1_NUMERICSTRING            = 0x12;
global_var ASN1_PRINTABLESTRING          = 0x13;
global_var ASN1_T61STRING                = 0x14;
global_var ASN1_TELETEXSTRING            = 0x14;## alias 
global_var ASN1_VIDEOTEXSTRING           = 0x15;
global_var ASN1_IA5STRING                = 0x16;
global_var ASN1_UTCTIME                  = 0x17;
global_var ASN1_GENERALIZEDTIME          = 0x18;
global_var ASN1_GRAPHICSTRING            = 0x19;
global_var ASN1_ISO64STRING              = 0x1a;
global_var ASN1_VISIBLESTRING            = 0x1a;## alias 
global_var ASN1_GENERALSTRING            = 0x1b;
global_var ASN1_UNIVERSALSTRING          = 0x1c;
global_var ASN1_BMPSTRING                = 0x1e;

