#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

if [[ "${1:-}" == "clean" ]]; then
	rm -rf build-elks
	exit 0
fi

if [[ -z "${TOPDIR:-}" ]]; then
	# shellcheck source=/dev/null
	source "$SCRIPT_DIR/../env.sh"
fi

# shellcheck source=/dev/null
source "$TOPDIR/libc/watcom.model"
MODEL=${MODEL:-l}
MEM_FLAG="-m${MODEL}"

if command -v wcc >/dev/null 2>&1; then
	WCC=${WCC:-$(command -v wcc)}
elif [[ -n "${WATCOM:-}" && -x $WATCOM/binl64/wcc ]]; then
	WCC=${WCC:-$WATCOM/binl64/wcc}
elif [[ -n "${WATCOM:-}" && -x $WATCOM/binl/wcc ]]; then
	WCC=${WCC:-$WATCOM/binl/wcc}
else
	WCC=${WCC:-wcc}
fi

if command -v wlib >/dev/null 2>&1; then
	WLIB=${WLIB:-$(command -v wlib)}
elif [[ -n "${WATCOM:-}" && -x $WATCOM/binl64/wlib ]]; then
	WLIB=${WLIB:-$WATCOM/binl64/wlib}
elif [[ -n "${WATCOM:-}" && -x $WATCOM/binl/wlib ]]; then
	WLIB=${WLIB:-$WATCOM/binl/wlib}
else
	WLIB=${WLIB:-wlib}
fi

CCOPTS="-os -bt=none -0 -zq -s ${MEM_FLAG} -wx -zastd=c99 -zls"

INCLUDES=(
	-i="$SCRIPT_DIR/Project"
	-i="$TOPDIR/include"
	-i="$TOPDIR/libc/include"
	-i="$TOPDIR/elks/include"
	-i="$TOPDIR/libc/include/watcom"
	-i="$TOPDIR/libc/include/c86"
)

SOURCES=(
	aes.c
	asn1parse.c
	asn1write.c
	base64.c
	bignum.c
	cipher.c
	cipher_wrap.c
	constant_time.c
	ctr_drbg.c
	debug.c
	entropy.c
	entropy_elks.c
	error.c
	md.c
	md5.c
	oid.c
	pem.c
	pk.c
	pkparse.c
	pk_wrap.c
	platform.c
	platform_util.c
	rsa.c
	rsa_internal.c
	sha1.c
	sha256.c
	ssl_ciphersuites.c
	ssl_cli.c
	ssl_msg.c
	ssl_tls.c
	MacSSL.c
	version.c
	x509.c
	x509_crt.c
	x509_crl.c
	x509_csr.c
	x509write_crt.c
	x509write_csr.c
)

BUILD_ROOT="$SCRIPT_DIR/build-elks"
OBJ_DIR="$BUILD_ROOT/obj"
LIB_DIR="$BUILD_ROOT/lib"
INCLUDE_DIR="$BUILD_ROOT/include"

mkdir -p "$OBJ_DIR" "$LIB_DIR" "$INCLUDE_DIR"

OBJ_FILES=()
for src in "${SOURCES[@]}"; do
	obj="$OBJ_DIR/${src%.c}.obj"
	echo "$WCC $CCOPTS ${INCLUDES[*]} Project/$src -fo=$obj"
	"$WCC" $CCOPTS "${INCLUDES[@]}" "Project/$src" -fo="$obj"
	OBJ_FILES+=("$obj")
done

LIB_FILE="$LIB_DIR/elkssl.lib"
rm -f "$LIB_FILE"
"$WLIB" -q -b -n "$LIB_FILE"
for obj in "${OBJ_FILES[@]}"; do
	"$WLIB" -q "$LIB_FILE" +"$obj"
done
rm -f "$LIB_DIR/elkssl.bak"

cp Project/*.h "$INCLUDE_DIR/"

find "$OBJ_DIR" -name '*.obj' -delete
find "$OBJ_DIR" -name '*.err' -delete
find "$OBJ_DIR" -name '*.lst' -delete

echo "Created $LIB_FILE"
