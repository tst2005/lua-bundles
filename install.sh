#!/bin/sh

set -e

[ -d ~/.lua-bundles ] || git clone https://github.com/tst2005/generated-bundle ~/.lua-bundles
cd ~/.lua-bundles
git pull

if [ ! -d lua-mini ]; then
	git clone https://github.com/tst2005/lua-mini
fi
cd lua-mini && {
	git checkout dev && git pull -q
	cd ..
}

[ -d mini ] || ln -s lua-mini/mini mini
[ -f tprint.lua ] || ln -s mini/tprint.lua tprint.lua

if [ ! -d lua-moses ]; then
	git clone https://github.com/Yonaba/Moses lua-moses ## tag ?
fi
if [ ! -e moses.lua ]; then
	ln -s lua-moses/moses_min.lua moses.lua
fi
cd lua-moses && {
	#git checkout dev &&
	git pull -q
        cd ..
}

echo "Add to your .bashrc:"
echo 'export LUA_PATH="${HOME:-~}/.lua-bundles/?.lua;${HOME:-~}/.lua-bundles/?/init.lua;;'
