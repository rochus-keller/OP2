#!/bin/bash
set -e

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <Module1.Obj> [Module2.Obj ...]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MULTIBOOTLINKER="${SCRIPT_DIR}/multibootlinker"

PAYLOAD_BIN="payload.bin"
PAYLOAD_OBJ="payload.o"
OUTPUT_EXE="a.out"

echo "[1/4] Generating raw located binary using multibootlinker..."
"$MULTIBOOTLINKER" --arch i386 --base 0x08049000 --autofix -o "$PAYLOAD_BIN" "$@"

echo "[2/4] Converting flat binary to an ELF32 object file..."
objcopy -I binary -O elf32-i386 --rename-section .data=.text,contents,alloc,load,code "$PAYLOAD_BIN" "$PAYLOAD_OBJ"

echo "[3/4] Generating strict Linker Script..."
cat > link.ld <<EOF
OUTPUT_FORMAT("elf32-i386")
ENTRY(_binary_payload_bin_start)
PHDRS {
  flat PT_LOAD FLAGS(7);
}
SECTIONS {
  . = 0x08049000;
  .text : { *(.text) } :flat
}
EOF

echo "[4/4] Linking into final Linux executable..."
ld -m elf_i386 -T link.ld "$PAYLOAD_OBJ" -o "$OUTPUT_EXE"

echo "Cleaning up temporary files..."
rm -f "$PAYLOAD_BIN" "$PAYLOAD_OBJ" "${PAYLOAD_BIN}.Link" link.ld

echo "Success! Executable created as ./${OUTPUT_EXE}"
