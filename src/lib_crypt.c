/*
** Crypt library.
*/

////////////////////////////////
#include <libhashsum.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "lj_lib.h"

////////////////////////////////
#define _CRYPT_MT "_crypt_mt"

////////////////////////////////
int _crypt_hash(lua_State *L, enum libhashsum_algorithm algo, size_t bits) {
  const char *s = NULL;
  size_t lenIn = 0;
  if (lua_type(L, 1)==LUA_TSTRING) {
    s = luaL_checklstring(L, 1, &lenIn);
  } else {
    luaL_error(L, "_crypt_hash() wrong type");
    return 0;
  }
  struct libhashsum_hasher hs;
  int r = 0;
  if (algo==LIBHASHSUM_BLAKE2B) {
    r = libhashsum_init_blake2b_hasher(&hs, bits, NULL, NULL, NULL, 0);
  } else {
    r = libhashsum_init_hasher(&hs, algo);
  }
  if (r!=0) {
    luaL_error(L, "_crypt_hash() failed");
    return 0;
  }
  if (lenIn>102400) {
    luaL_error(L, "_crypt_hash() too large");
    return 0;
  }
  r = hs.finalise_const(&hs, s, lenIn, 0);
  if (r!=0 || hs.hash_size==0 || hs.hash_output==NULL) {
    luaL_error(L, "_crypt_hash() failed");
    return 0;
  }
  lua_pushlstring(L, (const char*)hs.hash_output, hs.hash_size);
  if (hs.destroy!=NULL) {
    hs.destroy(&hs);
  }
  return 1;
}

////////////////////////////////
static int crypt_sha256(lua_State *L) {
  return _crypt_hash(L, LIBHASHSUM_SHA_256, 0);
}

////////////////////////////////
static int crypt_sha512(lua_State *L) {
  return _crypt_hash(L, LIBHASHSUM_SHA_512, 0);
}

////////////////////////////////
static int crypt_keccak256(lua_State *L) {
  return _crypt_hash(L, LIBHASHSUM_KECCAK_256, 0);
}

////////////////////////////////
static int crypt_keccak512(lua_State *L) {
  return _crypt_hash(L, LIBHASHSUM_KECCAK_512, 0);
}

////////////////////////////////
static int crypt_blake2b256(lua_State *L) {
  return _crypt_hash(L, LIBHASHSUM_BLAKE2B, 256);
}

////////////////////////////////
static int crypt_blake2b512(lua_State *L) {
  return _crypt_hash(L, LIBHASHSUM_BLAKE2B, 512);
}

////////////////////////////////
static int crypt_ripemd160(lua_State *L) {
  return _crypt_hash(L, LIBHASHSUM_RIPEMD_160, 0);
}

////////////////////////////////
#define _CRYPT_BECH32_CTABLE "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#define _CRYPT_BECH32_NTABLE {15,-1,10,17,21,20,26,30,7,5,-1,-1,-1,-1,-1,-1,-1,29,-1,24,13,25,9,8,23,-1,18,22,31,27,19,-1,1,0,3,16,11,28,12,14,6,4,2,-1,-1,-1,-1,-1,-1,29,-1,24,13,25,9,8,23,-1,18,22,31,27,19,-1,1,0,3,16,11,28,12,14,6,4,2};

////////////////////////////////
inline void _crypt_bit8to5(const uint8_t *s, size_t len, uint8_t *b5) {
  uint32_t buff = 0;
  int bits = 0;
  size_t j = 0;
  for (size_t i=0; i<len; i++) {
      buff = (buff<<8) | s[i];
      bits += 8;
      while (bits>=5) {
          bits -= 5;
          b5[j++] = (buff>>bits) & 31;
      }
  }
  if (bits>0) b5[j++] = (buff<<(5-bits)) & 31;
}

////////////////////////////////
inline void _crypt_bit5to8(const uint8_t *s, size_t len, uint8_t *b8) {
  uint32_t buff = 0;
  int bits = 0;
  size_t j = 0;
  for (size_t i=0; i<len; i++) {
      buff = (buff<<5) | s[i];
      bits += 5;
      while (bits>=8) {
          bits -= 8;
          b8[j++] = (buff>>bits) & 0xff;
      }
  }
}

////////////////////////////////
inline void _crypt_bech32x_hrp(const char *hrp, size_t len, uint8_t *b5) {
  for (size_t i=0; i<len; i++) {
    b5[i] = hrp[i] & 31;
  }
  b5[len] = 0;
}

////////////////////////////////
inline uint64_t _crypt_bech32x_polymod(const uint8_t *b5, size_t len) {
    uint64_t g[] = {0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470};
    uint64_t cs = 1;
    for (size_t i=0; i<len; i++) {
        uint64_t b = cs >> 35;
        cs = ((cs&0x07ffffffff)<<5) ^ b5[i];
        for (size_t j=0; j<5; j++) {
            if ((b>>j)&1) cs ^= g[j];
        }
    }
    return (cs^1) & 0xffffffffff;
}

////////////////////////////////
static int crypt_encbech32x(lua_State *L) {
  const char *s = NULL;
  size_t lenIn = 0;
  if (lua_type(L,1)==LUA_TSTRING) {
    s = luaL_checklstring(L, 1, &lenIn);
  } else {
    luaL_error(L, "crypt_encbech32x() wrong type");
    return 0;
  }
  const char *hrp = NULL;
  if (lua_type(L,2)==LUA_TSTRING) {
    hrp = luaL_checkstring(L, 2);
  } else {
    luaL_error(L, "crypt_encbech32x() wrong type");
    return 0;
  }
  size_t lenHrp = strlen(hrp);
  size_t b5len = (lenIn*8+4)/5 + lenHrp + 9;
  if (b5len>1023) {
      luaL_error(L, "crypt_encbech32x() too large");
      return 0;
  }
  uint8_t *b5 = malloc(b5len+1);
  if (b5==NULL) {
      luaL_error(L, "crypt_encbech32x() failed");
      return 0;
  }
  memset(b5+(b5len-8), 0, 9);
  _crypt_bech32x_hrp(hrp, lenHrp, b5);
  _crypt_bit8to5((uint8_t*)s, lenIn, b5+lenHrp+1);
  uint64_t p = _crypt_bech32x_polymod(b5, b5len);
  for (size_t i=0; i<8; i++) {
    b5[b5len-8+i] = (p>>(5*(7-i))) & 31;
  }
  memcpy(b5, hrp, lenHrp);
  b5[lenHrp] = ':';
  const char *cTable = _CRYPT_BECH32_CTABLE;
  for (size_t i=lenHrp+1; i<b5len; i++) {
    b5[i] = cTable[b5[i]];
  }
  lua_pushstring(L, (char*)b5);
  free(b5);
  return 1;
}

////////////////////////////////
static int crypt_decbech32x(lua_State *L) {
  const char *s = NULL;
  if (lua_type(L,1)==LUA_TSTRING) {
    s = luaL_checkstring(L, 1);
  } else {
    luaL_error(L, "crypt_decbech32x() wrong type");
    return 0;
  }
  size_t lenIn = strlen(s);
  if (lenIn>1023) {
      luaL_error(L, "crypt_decbech32x() too large");
      return 0;
  }
  size_t lenHrp = 0;
  for (size_t i=0; i<lenIn; i++) {
    if (s[i]==':') { lenHrp = i; break; }
  }
  if (lenHrp==0) {
    lua_pushstring(L, "");
    return 1;
  }
  uint8_t *b5 = malloc(lenIn);
  if (b5==NULL) {
      luaL_error(L, "crypt_decbech32x() failed");
      return 0;
  }
  _crypt_bech32x_hrp(s, lenHrp, b5);
  const int8_t nTable[] = _CRYPT_BECH32_NTABLE;
  for (size_t i=lenHrp+1; i<lenIn; i++) {
    int8_t j = s[i] - '0';
    if (j<0 || j>('z'-'0') || (j=nTable[j])<0) {
      free(b5);
      lua_pushstring(L, "");
      return 1;
    }
    b5[i] = j;
  }
  uint64_t p = _crypt_bech32x_polymod(b5, lenIn);
  if (p!=0) {
    free(b5);
    lua_pushstring(L, "");
    return 1;
  }
  size_t b8len = ((lenIn-lenHrp-9)*5)/8;
  uint8_t *b8 = malloc(b8len);
  _crypt_bit5to8((uint8_t*)b5+lenHrp+1, lenIn-lenHrp-9, b8);
  lua_pushlstring(L, (const char*)b8, b8len);
  free(b8);
  free(b5);
  return 1;
}

// ...

////////////////////////////////
static const luaL_Reg crypt_funcs[] = {
  {"sha256", crypt_sha256},
  {"sha512", crypt_sha512},
  {"keccak256", crypt_keccak256},
  {"keccak512", crypt_keccak512},
  {"blake2b256", crypt_blake2b256},
  {"blake2b512", crypt_blake2b512},
  {"ripemd160", crypt_ripemd160},
  {"encbech32x", crypt_encbech32x},
  {"decbech32x", crypt_decbech32x},
  // ...
  {NULL, NULL}
};

////////////////////////////////
LUALIB_API int luaopen_crypt(lua_State *L) {
  luaL_newmetatable(L, _CRYPT_MT);
  luaL_setfuncs(L, crypt_funcs, 0);
  lua_pushstring(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3);
  lua_setglobal(L, "crypt");
  return 1;
}
