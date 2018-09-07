do
	local loaded = require"package".loaded
	if loaded.json then
		loaded.json = nil
	end
	local m = require "json"
	if m and not loaded.json then
		loaded.json = m
	end
end
return require "json"
