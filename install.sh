#!/bin/sh

Result() {
	local r=$?;
	if [ $r -eq 0 ]; then
		echo >&2 "ok: $*";
	else
		echo >&2 "KO: $*";
	fi
	return $r;
}

directory_needed() {
	[ -d "$1" ] || mkdir -- "$1"
	[ -d "$1" ] || return 1
}
symlink_needed() {
	local basedir="$1" src="$2" dst="$3"; shift 3;
	(
		cd -- "$basedir" &&
		if [ ! -e "$dst" ]; then
			ln -s "$src" "$dst"
		fi
	)
}
get_or_update_git() {
	local basedir="$1" url="$2" subdir="$3";shift 3
	local br=''
	if [ $# -gt 0 ]; then
		br="$1";shift;
	fi
	if [ -d "$basedir/$subdir" ]; then
		if [ -n "$br" ]; then
			( cd -- "$basedir/$subdir" && git checkout "$br"; Result "branch $br" ) || return 1
		fi
		if ! ${noupdate:-false}; then
			( cd -- "$basedir/$subdir" && git pull -q; Result "git pull -> $basedir/$subdir" )
		fi
	else
		if [ -n "$br" ]; then
			( cd -- "$basedir" && git clone -q --branch "$br" "$url" "$subdir";  Result "git clone (branch $br) -> $basedir/$subdir" )
		else
			( cd -- "$basedir" && git clone -q "$url" "$subdir"; Result "git clone -> $basedir/$subdir" )
		fi
	fi
}

#no_update=false

set -e

get_or_update_git ~/ https://github.com/tst2005/lua-bundles .lua-bundles

cd -- ~/.lua-bundles/bundles &&
{
	get_or_update_git . https://github.com/tst2005/lua-mini lua-mini dev
	symlink_needed . lua-mini/mini mini
	symlink_needed . mini/tprint.lua tprint.lua

	get_or_update_git . https://github.com/Yonaba/Moses lua-moses ## tag ?
	symlink_needed . lua-moses/moses_min.lua moses.lua

	get_or_update_git . https://github.com/tst2005/lua-uniformapi lua-uniformapi
	symlink_needed . lua-uniformapi/uniformapi.lua uniformapi.lua
	symlink_needed . lua-uniformapi/uniformapi uniformapi

	get_or_update_git . https://github.com/tst2005/lua-utf8string lua-utf8string
	symlink_needed . lua-utf8string/utf8string.lua utf8string.lua

	echo 'export LUA_PATH="${LUA_PATH:+$LUA_PATH;}./?.lua;./?/init.lua;${HOME:-~}/.lua-bundles/bundles/?.lua;${HOME:-~}/.lua-bundles/bundles/?/init.lua;;"' > ../env.sh
}
echo >&2 "Add to your .bashrc:"
echo >&2 '[ ! -r "${HOME:-~}/.lua-bundles/env.sh" ] || . "${HOME:-~}/.lua-bundles/env.sh"'

