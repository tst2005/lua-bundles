#!/bin/sh
set -e
[ -d ~/.lua-bundles ] || git clone https://github.com/tst2005/generated-bundle ~/.lua-bundles
cd ~/.lua-bundles
git clone https://github.com/tst2005/lua-mini
[ -d mini ] || ln -s lua-mini/mini mini
[ -f tprint.lua ] || ln -s mini/tprint.lua tprint.lua

git clone https://github.com/Yonaba/Moses lua-moses ## tag ?
ln -s lua-moses/moses_min.lua moses.lua


# export LUA_PATH="${HOME:-~}/.lua-bundles/?.lua;;"
