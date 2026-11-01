#!/bin/bash

arch_offset() {
	lipo -detailed_info "$1" 2>/dev/null |
	awk '/architecture x86_64/{f=1} f && /^ *offset/{print $2; exit}'
}

find /usr/lib /System/Library -type f \
	\( -name '*.dylib' -o \( -path '*/Versions/*' -perm +111 \) \) 2>/dev/null |
sort |
while read -r f; do
	id=$(otool -D "$f" 2>/dev/null | sed -n '2p')
	[ -n "$id" ] || continue
	id=$(echo "$id" | tr -d '\t' | tr 'A-Z' 'a-z')
	otool -l "$f" 2>/dev/null | awk '/LC_REEXPORT_DYLIB/{getline; getline; print tolower($2)}' |
	while read -r re; do
		[ -n "$re" ] && echo "$id REEXPORT $re"
	done
	{ nm -arch x86_64 -gjU "$f" 2>/dev/null; } | sort -u | grep -v '^$' |
	while read -r s; do
		echo "$id $s"
	done
	eoff=$(otool -l "$f" 2>/dev/null | awk '/LC_DYLD_INFO/{f=1} f && /^ *export_off/{print $2; exit}')
	esz=$(otool -l "$f" 2>/dev/null | awk '/LC_DYLD_INFO/{f=1} f && /^ *export_size/{print $2; exit}')
	if [ -n "$eoff" ] && [ -n "$esz" ] && [ "$esz" -gt 0 ]; then
		abs=$(( $(arch_offset "$f") + eoff ))
		trie=$(tail -c "+$((abs + 1))" "$f" 2>/dev/null | head -c "$esz" | base64 | tr -d '\n')
		[ -n "$trie" ] && echo "$id TRIE $trie"
	fi
done
