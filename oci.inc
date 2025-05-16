#TRUSTED 672f014f10c6729e1efedc28d0bab0e8b0189c580bb438ff58a2e8c797e92b8b78f6c8604b0aa7c2f4692ba66f766243dff1fd73ae49bc4a84bf4102c7244ec7a0040ea9271a18da1d0f2e1b6287df4fd902424b3cabcd7eb7824ee0f69dc4a2b86e8bd5f9eeeae6f3cf122828f04808a869cf9eb5fbfff451a8156c4712d00c9aa997638745996202786661338d97ee70bdacfa14fc7959e29cc2b2f05ea87384061c936664be99947cb428d159f172bfa7896a69c257b29c7d791b5a0630a2d608c1aaf7182141a2f198d44c3f56e53c881ffac02a859c0b7e7eac470250bf74671cf665a120f4de7714f83fb6f6f6367bdd29616a03fdabb37db393f04cc84ac573cd703c06065ca20b1f1ae803c1623aea2fa295cf552314339653b9a384c0104b19836a5753bb18d23da5c44eacd5a8c894ca28a9cbbaf5e1473dbf7757be2a646b39a656cda7cc46bc141bb2e920895c7fec3552884ea6486be008b3968f406be65dc13ab56d357ef4a0dfba083f2a2fc022b532dd09479e3fd9b52cd65a8516be5d3ad0b40e46575894f99cbb2941340d3b0da2c5152ab2993440c69e661a02c45a5d1ecf69361a3675a169ee686f57d9beaa7b4dd3891790a3838153ee6acd0c9ec4b37050c0e7c71b69406369d25167629dd718f6ed238addd290123a511ccecbfdfd3bec042d84e21f59f1656190b6a61b18613874223830d7497e
#
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# 
# oci.inc
# Revision: 1.12
#

global_var OCI_API_V1_ROOT, OCI_API_V2_ROOT, OCI_API_HOST, OCI_API_ITEMS, OCI_HOST_TAG_BASE, OCI_KB_BASE;
global_var OCI_IMDSV2_HEADER, OCI_API_ENDPOINT;

##
# API Host
##
OCI_API_HOST = '169.254.169.254';

##
# API Endpoint
##
OCI_API_ENDPOINT = 'http://' + OCI_API_HOST;

##
# API V1 Root
##
OCI_API_V1_ROOT  = '/opc/v1/';

##
# API V2 Root
##
OCI_API_V2_ROOT  = '/opc/v2/';

##
# IMDS v2 Request Header
##
OCI_IMDSV2_HEADER = 'Authorization: Bearer Oracle';

##
# XML Host Tag base
##
OCI_HOST_TAG_BASE = 'oci-instance';

##
# KB Base
##
OCI_KB_BASE = 'Host/OCI';

##
# Metadata API Items
##
OCI_API_ITEMS = ['instance', 'vnics', 'volumeAttachments'];

