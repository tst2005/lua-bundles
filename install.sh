#!/bin/sh

. ./util.lib.sh

#no_update=false

set -e

# I'm install.sh
# $0 can be
# install.sh
# ./install.sh
# /home/USER/.lua-bundles/install.sh
# /another/path/to/install.sh
# /anything/else/foo.sh if the user rename the script ...

# 1. detect the current path
# 2. cut to have a the lua-bundles repo directory (where install.sh should be)
# 3. install inside this dir ?
# 4. generate the env.sh

# the next line is useless with the new way to install
#get_or_update_git ~/ https://github.com/tst2005/lua-bundles .lua-bundles
# but we should have :
#update_git ~ .lua-bundles

get_or_update_git ~ https://github.com/tst2005/lua-bundles .lua-bundles

# FIXME: the next line ...
cd -- ~/.lua-bundles &&

cd -- ./bundles &&
{
	get_or_update_in_branch_git . https://github.com/tst2005/lua-mini lua-mini dev
	symlink_needed . lua-mini/mini mini
	symlink_needed . mini/tprint.lua tprint.lua

	get_or_update_git . https://github.com/Yonaba/Moses lua-moses ## tag ?
	symlink_needed . lua-moses/moses_min.lua moses.lua

	get_or_update_git . https://github.com/tst2005/lua-uniformapi lua-uniformapi
	symlink_needed . lua-uniformapi/uniformapi.lua uniformapi.lua
	symlink_needed . lua-uniformapi/uniformapi uniformapi

	get_or_update_git . https://github.com/tst2005/lua-utf8string lua-utf8string
	symlink_needed . lua-utf8string/utf8string.lua utf8string.lua

	get_or_update_git . https://github.com/tst2005/lua-semver lua-semver
	symlink_needed . lua-semver/semver.lua semver.lua

	echo 'export LUA_PATH="${LUA_PATH:+$LUA_PATH;}./?.lua;./?/init.lua;${HOME:-~}/.lua-bundles/bundles/?.lua;${HOME:-~}/.lua-bundles/bundles/?/init.lua;;"' > ../env.sh
}
echo >&2 "Add to your .bashrc:"
echo >&2 '[ ! -r "${HOME:-~}/.lua-bundles/env.sh" ] || . "${HOME:-~}/.lua-bundles/env.sh"'

