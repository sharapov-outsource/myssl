/**
 * Cipher suite registry.
 *
 * Only the IANA number and name are stored; everything else (key exchange,
 * authentication, cipher, key length, mode, MAC) is derived from the name,
 * because those names are strictly structured:
 *
 *     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *         └─kx─┘ └au┘      └ cipher ┘ └mac┘
 *
 * A suite missing from the table is still reported — under its hex number and
 * with unknown properties — so an exotic server never breaks the scan.
 */

/** IANA number → registry name. */
export const SUITE_NAMES = {
  /* ---- TLS 1.3 ---- */
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0x1304: 'TLS_AES_128_CCM_SHA256',
  0x1305: 'TLS_AES_128_CCM_8_SHA256',

  /* ---- SSL 3.0 / TLS 1.0 core ---- */
  0x0000: 'TLS_NULL_WITH_NULL_NULL',
  0x0001: 'TLS_RSA_WITH_NULL_MD5',
  0x0002: 'TLS_RSA_WITH_NULL_SHA',
  0x0003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
  0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
  0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
  0x0006: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
  0x0007: 'TLS_RSA_WITH_IDEA_CBC_SHA',
  0x0008: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
  0x0009: 'TLS_RSA_WITH_DES_CBC_SHA',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  0x000b: 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
  0x000c: 'TLS_DH_DSS_WITH_DES_CBC_SHA',
  0x000d: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
  0x000e: 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
  0x000f: 'TLS_DH_RSA_WITH_DES_CBC_SHA',
  0x0010: 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
  0x0011: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
  0x0012: 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
  0x0013: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
  0x0014: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
  0x0015: 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
  0x0016: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
  0x0017: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
  0x0018: 'TLS_DH_anon_WITH_RC4_128_MD5',
  0x0019: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
  0x001a: 'TLS_DH_anon_WITH_DES_CBC_SHA',
  0x001b: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',

  /* ---- Kerberos ---- */
  0x001e: 'TLS_KRB5_WITH_DES_CBC_SHA',
  0x001f: 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
  0x0020: 'TLS_KRB5_WITH_RC4_128_SHA',
  0x0023: 'TLS_KRB5_WITH_DES_CBC_MD5',
  0x0024: 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
  0x0025: 'TLS_KRB5_WITH_RC4_128_MD5',

  /* ---- AES CBC (TLS 1.0+) ---- */
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0030: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
  0x0031: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
  0x0032: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
  0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
  0x0034: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x0036: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
  0x0037: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
  0x0038: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
  0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
  0x003a: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',

  /* ---- SHA-256 variants (TLS 1.2) ---- */
  0x003b: 'TLS_RSA_WITH_NULL_SHA256',
  0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
  0x003d: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
  0x003e: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
  0x003f: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
  0x0040: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',

  /* ---- Camellia CBC SHA ---- */
  0x0041: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
  0x0042: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
  0x0043: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
  0x0044: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
  0x0045: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
  0x0046: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',

  /* ---- 1024-bit export suites ---- */
  0x0060: 'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5',
  0x0061: 'TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5',
  0x0062: 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
  0x0063: 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
  0x0064: 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA',
  0x0065: 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
  0x0066: 'TLS_DHE_DSS_WITH_RC4_128_SHA',

  0x0067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
  0x0068: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
  0x0069: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
  0x006a: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
  0x006b: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
  0x006c: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
  0x006d: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',

  /* ---- Camellia 256 CBC SHA ---- */
  0x0084: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
  0x0085: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
  0x0086: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
  0x0087: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
  0x0088: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
  0x0089: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',

  /* ---- PSK ---- */
  0x008a: 'TLS_PSK_WITH_RC4_128_SHA',
  0x008b: 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
  0x008c: 'TLS_PSK_WITH_AES_128_CBC_SHA',
  0x008d: 'TLS_PSK_WITH_AES_256_CBC_SHA',
  0x008e: 'TLS_DHE_PSK_WITH_RC4_128_SHA',
  0x008f: 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
  0x0090: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
  0x0091: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
  0x0092: 'TLS_RSA_PSK_WITH_RC4_128_SHA',
  0x0093: 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
  0x0094: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
  0x0095: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',

  /* ---- SEED ---- */
  0x0096: 'TLS_RSA_WITH_SEED_CBC_SHA',
  0x0097: 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
  0x0098: 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
  0x0099: 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
  0x009a: 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
  0x009b: 'TLS_DH_anon_WITH_SEED_CBC_SHA',

  /* ---- AES GCM (TLS 1.2) ---- */
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x009e: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
  0x009f: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
  0x00a0: 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
  0x00a1: 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
  0x00a2: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
  0x00a3: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
  0x00a4: 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
  0x00a5: 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
  0x00a6: 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
  0x00a7: 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
  0x00a8: 'TLS_PSK_WITH_AES_128_GCM_SHA256',
  0x00a9: 'TLS_PSK_WITH_AES_256_GCM_SHA384',
  0x00aa: 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
  0x00ab: 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
  0x00ac: 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
  0x00ad: 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
  0x00ae: 'TLS_PSK_WITH_AES_128_CBC_SHA256',
  0x00af: 'TLS_PSK_WITH_AES_256_CBC_SHA384',
  0x00b0: 'TLS_PSK_WITH_NULL_SHA256',
  0x00b1: 'TLS_PSK_WITH_NULL_SHA384',
  0x00b2: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
  0x00b3: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
  0x00b4: 'TLS_DHE_PSK_WITH_NULL_SHA256',
  0x00b5: 'TLS_DHE_PSK_WITH_NULL_SHA384',
  0x00b6: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
  0x00b7: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
  0x00b8: 'TLS_RSA_PSK_WITH_NULL_SHA256',
  0x00b9: 'TLS_RSA_PSK_WITH_NULL_SHA384',

  /* ---- Camellia CBC SHA256 ---- */
  0x00ba: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0x00bb: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
  0x00bc: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0x00bd: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
  0x00be: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0x00bf: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
  0x00c0: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
  0x00c1: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
  0x00c2: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
  0x00c3: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
  0x00c4: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
  0x00c5: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',

  /* ---- signalling values ---- */
  0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
  0x5600: 'TLS_FALLBACK_SCSV',

  /* ---- elliptic curve suites ---- */
  0xc001: 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
  0xc002: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
  0xc003: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
  0xc004: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
  0xc005: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
  0xc006: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
  0xc007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
  0xc008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
  0xc009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
  0xc00a: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
  0xc00b: 'TLS_ECDH_RSA_WITH_NULL_SHA',
  0xc00c: 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
  0xc00d: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
  0xc00e: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
  0xc00f: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
  0xc010: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
  0xc011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
  0xc012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0xc015: 'TLS_ECDH_anon_WITH_NULL_SHA',
  0xc016: 'TLS_ECDH_anon_WITH_RC4_128_SHA',
  0xc017: 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
  0xc018: 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
  0xc019: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',

  /* ---- SRP ---- */
  0xc01a: 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
  0xc01b: 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
  0xc01c: 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
  0xc01d: 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
  0xc01e: 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
  0xc01f: 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
  0xc020: 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
  0xc021: 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
  0xc022: 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',

  /* ---- EC + SHA-2 ---- */
  0xc023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
  0xc024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
  0xc025: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
  0xc026: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
  0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  0xc028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
  0xc029: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
  0xc02a: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc02d: 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02e: 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xc031: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
  0xc032: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',

  /* ---- ECDHE_PSK ---- */
  0xc033: 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
  0xc034: 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
  0xc035: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
  0xc036: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
  0xc037: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
  0xc038: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
  0xc039: 'TLS_ECDHE_PSK_WITH_NULL_SHA',
  0xc03a: 'TLS_ECDHE_PSK_WITH_NULL_SHA256',
  0xc03b: 'TLS_ECDHE_PSK_WITH_NULL_SHA384',

  /* ---- ARIA ---- */
  0xc03c: 'TLS_RSA_WITH_ARIA_128_CBC_SHA256',
  0xc03d: 'TLS_RSA_WITH_ARIA_256_CBC_SHA384',
  0xc044: 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256',
  0xc045: 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384',
  0xc048: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
  0xc049: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
  0xc04c: 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
  0xc04d: 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
  0xc050: 'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
  0xc051: 'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
  0xc052: 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
  0xc053: 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
  0xc05c: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
  0xc05d: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
  0xc060: 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
  0xc061: 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',

  /* ---- Camellia with SHA-2 and GCM ---- */
  0xc072: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
  0xc073: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
  0xc074: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
  0xc075: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
  0xc076: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0xc077: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
  0xc078: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0xc079: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
  0xc07a: 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xc07b: 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xc07c: 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xc07d: 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xc086: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xc087: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xc08a: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xc08b: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',

  /* ---- CCM ---- */
  0xc09c: 'TLS_RSA_WITH_AES_128_CCM',
  0xc09d: 'TLS_RSA_WITH_AES_256_CCM',
  0xc09e: 'TLS_DHE_RSA_WITH_AES_128_CCM',
  0xc09f: 'TLS_DHE_RSA_WITH_AES_256_CCM',
  0xc0a0: 'TLS_RSA_WITH_AES_128_CCM_8',
  0xc0a1: 'TLS_RSA_WITH_AES_256_CCM_8',
  0xc0a2: 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
  0xc0a3: 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
  0xc0a4: 'TLS_PSK_WITH_AES_128_CCM',
  0xc0a5: 'TLS_PSK_WITH_AES_256_CCM',
  0xc0ac: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
  0xc0ad: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
  0xc0ae: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
  0xc0af: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',

  /* ---- ChaCha20-Poly1305 ---- */
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0xccaa: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xccab: 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256',
  0xccac: 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
  0xccad: 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
  0xccae: 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256',
  /* pre-standard ChaCha20 numbers, still seen in the wild */
  0xcc13: 'OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xcc14: 'OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0xcc15: 'OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
};

/** Suites that only signal something and are never negotiated. */
const SCSV = new Set([0x00ff, 0x5600]);

/** SSL 2.0 cipher specs are three bytes wide and live in their own registry. */
export const SSL2_SUITES = {
  0x010080: 'SSL_CK_RC4_128_WITH_MD5',
  0x020080: 'SSL_CK_RC4_128_EXPORT40_WITH_MD5',
  0x030080: 'SSL_CK_RC2_128_CBC_WITH_MD5',
  0x040080: 'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5',
  0x050080: 'SSL_CK_IDEA_128_CBC_WITH_MD5',
  0x060040: 'SSL_CK_DES_64_CBC_WITH_MD5',
  0x0700c0: 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5',
};

/* ------------------------------------------------------------------ *
 * Deriving properties from the name
 * ------------------------------------------------------------------ */

/** Symmetric cipher → effective key length in bits. */
const CIPHER_BITS = {
  NULL: 0,
  RC4_40: 40, RC2_40: 40, DES40: 40,
  RC4_56: 56, RC2_56: 56, DES: 56,
  '3DES': 112,          // 168 nominal, 112 effective against meet-in-the-middle
  IDEA: 128, SEED: 128,
  RC4_128: 128, RC2_128: 128,
  CHACHA20: 256,
};

const ALL_IDS = Object.keys(SUITE_NAMES).map(Number);

/** Every suite id the prober may offer, minus the signalling values. */
export function allSuiteIds() {
  return ALL_IDS.filter(id => !SCSV.has(id));
}

/** TLS 1.3 uses a separate, tiny registry. */
export const TLS13_IDS = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305];

export function hexId(id) {
  return '0x' + id.toString(16).toUpperCase().padStart(4, '0');
}

export function suiteName(id) {
  return SUITE_NAMES[id] || `UNKNOWN_${hexId(id)}`;
}

/** OpenSSL-style short name for the suites people usually see in configs. */
const OPENSSL_NAMES = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256',
  0xc030: 'ECDHE-RSA-AES256-GCM-SHA384',
  0xc02b: 'ECDHE-ECDSA-AES128-GCM-SHA256',
  0xc02c: 'ECDHE-ECDSA-AES256-GCM-SHA384',
  0xcca8: 'ECDHE-RSA-CHACHA20-POLY1305',
  0xcca9: 'ECDHE-ECDSA-CHACHA20-POLY1305',
  0xc013: 'ECDHE-RSA-AES128-SHA',
  0xc014: 'ECDHE-RSA-AES256-SHA',
  0xc027: 'ECDHE-RSA-AES128-SHA256',
  0xc028: 'ECDHE-RSA-AES256-SHA384',
  0x009c: 'AES128-GCM-SHA256',
  0x009d: 'AES256-GCM-SHA384',
  0x002f: 'AES128-SHA',
  0x0035: 'AES256-SHA',
  0x000a: 'DES-CBC3-SHA',
  0x0005: 'RC4-SHA',
};

const cache = new Map();

/**
 * Full description of a suite.
 *
 * @returns {{
 *   id:number, hex:string, name:string, openssl:string|undefined,
 *   keyExchange:string, authentication:string, encryption:string,
 *   bits:number|undefined, mode:string|undefined, mac:string|undefined,
 *   pfs:boolean, aead:boolean, export:boolean, anonymous:boolean,
 *   strength:'insecure'|'weak'|'legacy'|'strong', issues:string[]
 * }}
 */
export function describeSuite(id) {
  const hit = cache.get(id);
  if (hit) return hit;

  const name = suiteName(id);
  const known = Boolean(SUITE_NAMES[id]);
  const result = {
    id, hex: hexId(id), name, openssl: OPENSSL_NAMES[id],
    keyExchange: 'unknown', authentication: 'unknown', encryption: 'unknown',
    bits: undefined, mode: undefined, mac: undefined,
    pfs: false, aead: false, export: false, anonymous: false,
    strength: 'weak', issues: known ? [] : ['unknown-suite'],
  };

  if (known) Object.assign(result, parseName(name));
  cache.set(id, result);
  return result;
}

function parseName(fullName) {
  const name = fullName.replace(/^OLD_/, '');
  const out = {};

  // TLS 1.3 names carry no key exchange: it is always (EC)DHE with a
  // certificate or a PSK, decided by the handshake rather than the suite.
  if (/^TLS_(AES|CHACHA20)/.test(name)) {
    Object.assign(out, {
      keyExchange: 'ECDHE', authentication: 'any', pfs: true,
      ...parseCipher(name.replace(/^TLS_/, '')),
    });
    out.strength = 'strong';
    out.issues = [];
    return out;
  }

  const [left, right] = name.replace(/^TLS_/, '').split('_WITH_');
  Object.assign(out, parseKeyExchange(left));
  Object.assign(out, parseCipher(right ?? ''));

  const issues = [];
  if (out.export) issues.push('export');
  if (out.anonymous) issues.push('anonymous');
  if (out.encryption === 'NULL') issues.push('no-encryption');
  if (out.encryption === 'RC4') issues.push('rc4');
  if (out.encryption === '3DES') issues.push('sweet32');
  if (out.encryption === 'DES') issues.push('des');
  if (out.encryption === 'RC2') issues.push('rc2');
  if (out.encryption === 'IDEA') issues.push('idea');
  if (out.mac === 'MD5') issues.push('md5-mac');
  if (!out.pfs && !/PSK|SRP|KRB5/.test(left)) issues.push('no-pfs');
  if (out.mode === 'CBC') issues.push('cbc');
  if (typeof out.bits === 'number' && out.bits > 0 && out.bits < 128) issues.push('short-key');

  out.issues = issues;
  out.strength =
    (out.export || out.anonymous || out.encryption === 'NULL' ||
     (out.bits !== undefined && out.bits < 112)) ? 'insecure'
    : (out.encryption === 'RC4' || out.encryption === '3DES' || out.mac === 'MD5') ? 'weak'
    : (!out.pfs || out.mode === 'CBC') ? 'legacy'
    : 'strong';
  return out;
}

function parseKeyExchange(left) {
  const out = { export: /EXPORT/.test(left), anonymous: /_anon/.test(left) };
  const kx = left.replace(/_EXPORT(1024)?/, '');

  const table = [
    [/^ECDHE_ECDSA$/, 'ECDHE', 'ECDSA'],
    [/^ECDHE_RSA$/, 'ECDHE', 'RSA'],
    [/^ECDHE_PSK$/, 'ECDHE', 'PSK'],
    [/^ECDH_ECDSA$/, 'ECDH', 'ECDSA'],
    [/^ECDH_RSA$/, 'ECDH', 'RSA'],
    [/^ECDH_anon$/, 'ECDH', 'anon'],
    [/^DHE_RSA$/, 'DHE', 'RSA'],
    [/^DHE_DSS$/, 'DHE', 'DSS'],
    [/^DHE_PSK$/, 'DHE', 'PSK'],
    [/^DH_RSA$/, 'DH', 'RSA'],
    [/^DH_DSS$/, 'DH', 'DSS'],
    [/^DH_anon$/, 'DH', 'anon'],
    [/^RSA_PSK$/, 'RSA', 'PSK'],
    [/^RSA$/, 'RSA', 'RSA'],
    [/^PSK$/, 'PSK', 'PSK'],
    [/^SRP_SHA_RSA$/, 'SRP', 'RSA'],
    [/^SRP_SHA_DSS$/, 'SRP', 'DSS'],
    [/^SRP_SHA$/, 'SRP', 'anon'],
    [/^KRB5$/, 'KRB5', 'KRB5'],
    [/^NULL$/, 'NULL', 'NULL'],
  ];

  for (const [re, keyExchange, authentication] of table) {
    if (re.test(kx)) {
      out.keyExchange = keyExchange;
      out.authentication = authentication;
      break;
    }
  }
  out.keyExchange ??= 'unknown';
  out.authentication ??= 'unknown';
  out.pfs = out.keyExchange === 'ECDHE' || out.keyExchange === 'DHE';
  if (out.authentication === 'anon') out.anonymous = true;
  return out;
}

function parseCipher(right) {
  const out = {};
  if (!right) return { encryption: 'unknown' };

  // The MAC (or the PRF hash for AEAD suites) is the tail of the name.
  const macMatch = /_(MD5|SHA|SHA256|SHA384|SHA512)$/.exec(right);
  out.mac = macMatch ? macMatch[1] : undefined;
  let body = macMatch ? right.slice(0, -macMatch[0].length) : right;

  if (/^NULL/.test(body)) {
    return { ...out, encryption: 'NULL', bits: 0, mode: 'NULL' };
  }

  if (/^CHACHA20_POLY1305/.test(body)) {
    return { ...out, encryption: 'CHACHA20', bits: 256, mode: 'POLY1305', aead: true };
  }

  // A couple of export suites spell the key length after the mode
  // (RC2_CBC_40), so the two tokens are swapped back into the usual order.
  body = body.replace(/_CBC_(\d{2,3})$/, '_$1_CBC');

  // Mode is the last recognised token; CCM_8 is a truncated-tag CCM.
  let mode;
  if (/_CCM_8$/.test(body)) { mode = 'CCM_8'; body = body.replace(/_CCM_8$/, ''); }
  else if (/_CCM$/.test(body)) { mode = 'CCM'; body = body.replace(/_CCM$/, ''); }
  else if (/_GCM$/.test(body)) { mode = 'GCM'; body = body.replace(/_GCM$/, ''); }
  else if (/_CBC$/.test(body)) { mode = 'CBC'; body = body.replace(/_CBC$/, ''); }

  out.mode = mode;
  out.aead = mode === 'GCM' || mode === 'CCM' || mode === 'CCM_8';

  // What is left is the cipher and, usually, its key length: AES_128, DES40, RC4_128.
  const bitsMatch = /_(\d{2,3})$/.exec(body);
  const cipher = bitsMatch ? body.slice(0, -bitsMatch[0].length) : body;
  let bits = bitsMatch ? Number(bitsMatch[1]) : undefined;

  const family = cipher.replace(/_EDE$/, '');
  if (bits === undefined) {
    bits = CIPHER_BITS[family] ?? CIPHER_BITS[`${family}_${bitsMatch?.[1]}`];
  }
  if (family === '3DES') bits = CIPHER_BITS['3DES'];
  if (family === 'DES40') bits = 40;
  if (family === 'DES') bits = 56;
  if (family === 'RC2' && bits === 128) bits = 128;

  out.encryption = family === 'DES40' ? 'DES' : family;
  out.bits = bits;
  return out;
}
