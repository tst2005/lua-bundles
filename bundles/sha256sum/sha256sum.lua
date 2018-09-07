do --{{
local sources, priorities = {}, {};assert(not sources["lockbox.util.stream"],"module already exists")sources["lockbox.util.stream"]=([===[-- <pack lockbox.util.stream> --
local Queue = require("lockbox.util.queue");
local String = require("string");

local Stream = {};


Stream.fromString = function(string)
	local i=0;
	return function()
		i=i+1;
		if(i <= String.len(string)) then
			return String.byte(string,i);
		else
			return nil;
		end
	end
end


Stream.toString = function(stream)
	local array = {};
	local i=1;

	local byte = stream();
	while byte ~= nil do
		array[i] = String.char(byte);
		i = i+1;
		byte = stream();
	end

	return table.concat(array,"");
end


Stream.fromArray = function(array)
	local queue = Queue();
	local i=1;

	local byte = array[i];
	while byte ~= nil do
		queue.push(byte);
		i=i+1;
		byte = array[i];
	end

	return queue.pop;
end


Stream.toArray = function(stream)
	local array = {};
	local i=1;

	local byte = stream();
	while byte ~= nil do
		array[i] = byte;
		i = i+1;
		byte = stream();
	end

	return array;
end


local fromHexTable = {};
for i=0,255 do
	fromHexTable[String.format("%02X",i)]=i;
	fromHexTable[String.format("%02x",i)]=i;
end

Stream.fromHex = function(hex)
	local queue = Queue();

	for i=1,String.len(hex)/2 do
		local h = String.sub(hex,i*2-1,i*2);
		queue.push(fromHexTable[h]);
	end

	return queue.pop;
end



local toHexTable = {};
for i=0,255 do
	toHexTable[i]=String.format("%02X",i);
end

Stream.toHex = function(stream)
	local hex = {};
	local i = 1;

	local byte = stream();
	while byte ~= nil do
		hex[i] = toHexTable[byte];
		i=i+1;
		byte = stream();
	end

	return table.concat(hex,"");
end

return Stream;
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["lockbox.util.bit"],"module already exists")sources["lockbox.util.bit"]=([===[-- <pack lockbox.util.bit> --
local ok, e
if not ok then
	ok, e = pcall(require, "bit") -- the LuaJIT one ?
end
if not ok then
	ok, e = pcall(require, "bit32") -- Lua 5.2
end
if not ok then
	ok, e = pcall(require, "bit.numberlua") -- for Lua 5.1, https://github.com/tst2005/lua-bit-numberlua/
end
if not ok then
	error("no bitwise support found", 2)
end
assert(type(e)=="table", "invalid bit module")

-- Workaround to support Lua 5.2 bit32 API with the LuaJIT bit one
if e.rol and not e.lrotate then
	e.lrotate = e.rol
end
if e.ror and not e.rrotate then
	e.rrotate = e.ror
end

return e
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["lockbox.mac.hmac"],"module already exists")sources["lockbox.mac.hmac"]=([===[-- <pack lockbox.mac.hmac> --
local Bit = require("lockbox.util.bit");
local String = require("string");
local Stream = require("lockbox.util.stream");
local Array = require("lockbox.util.array");

local XOR = Bit.bxor;

local HMAC = function()

	local public = {};
	local blockSize = 64;
	local Digest = nil;
	local outerPadding = {};
	local innerPadding = {}
	local digest;

	public.setBlockSize = function(bytes)
		blockSize = bytes;
		return public;
	end

	public.setDigest = function(digestModule)
		Digest = digestModule;
		digest = Digest();
		return public;
	end

	public.setKey = function(key)
		local keyStream;

		if(Array.size(key) > blockSize) then
			keyStream = Stream.fromArray(Digest()
						.update(Stream.fromArray(key))
						.finish()
						.asBytes());
		else
			keyStream = Stream.fromArray(key);
		end

		outerPadding = {};
		innerPadding = {};

		for i=1,blockSize do
			local byte = keyStream();
			if byte == nil then byte = 0x00; end
			outerPadding[i] = XOR(0x5C,byte);
			innerPadding[i] = XOR(0x36,byte);
		end

		return public;
	end

	public.init = function()
		digest	.init()
				.update(Stream.fromArray(innerPadding));
		return public;
	end

	public.update = function(messageStream)
		digest.update(messageStream);
		return public;
	end

	public.finish = function()
		local inner = digest.finish().asBytes();
		digest	.init()
				.update(Stream.fromArray(outerPadding))
				.update(Stream.fromArray(inner))
				.finish();

		return public;
	end

	public.asBytes = function()
		return digest.asBytes();
	end

	public.asHex = function()
		return digest.asHex();
	end

	return public;

end

return HMAC;
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["lockbox.util.queue"],"module already exists")sources["lockbox.util.queue"]=([===[-- <pack lockbox.util.queue> --
local Queue = function()
	local queue = {};
	local tail = 0;
	local head = 0;

	local public = {};

	public.push = function(obj)
		queue[head] = obj;
		head = head + 1;
		return;
	end

	public.pop = function()
		if tail < head
		then
			local obj = queue[tail];
			queue[tail] = nil;
			tail = tail + 1;
			return obj;
		else
			return nil;
		end
	end

	public.size = function()
		return head - tail;
	end

	public.getHead = function()
		return head;
	end

	public.getTail = function()
		return tail;
	end

	public.reset = function()
		queue = {};
		head = 0;
		tail = 0;
	end

	return public;
end

return Queue;
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["lockbox.digest.sha2_256"],"module already exists")sources["lockbox.digest.sha2_256"]=([===[-- <pack lockbox.digest.sha2_256> --
local Bit = require("lockbox.util.bit");
local String = require("string");
local Math = require("math");
local Queue = require("lockbox.util.queue");

local CONSTANTS = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2  };

local AND = Bit.band;
local OR  = Bit.bor;
local NOT = Bit.bnot;
local XOR = Bit.bxor;
local LROT = Bit.lrotate;
local RROT = Bit.rrotate;
local LSHIFT = Bit.lshift;
local RSHIFT = Bit.rshift;

--SHA2 is big-endian
local bytes2word = function(b0,b1,b2,b3)
	local i = b0; i = LSHIFT(i,8);
	i = OR(i,b1); i = LSHIFT(i,8);
	i = OR(i,b2); i = LSHIFT(i,8);
	i = OR(i,b3);
	return i;
end

local word2bytes = function(word)
	local b0,b1,b2,b3;
	b3 = AND(word,0xFF); word = RSHIFT(word,8);
	b2 = AND(word,0xFF); word = RSHIFT(word,8);
	b1 = AND(word,0xFF); word = RSHIFT(word,8);
	b0 = AND(word,0xFF);
	return b0,b1,b2,b3;
end

local bytes2dword = function(b0,b1,b2,b3,b4,b5,b6,b7)
	local i = bytes2word(b0,b1,b2,b3);
	local j = bytes2word(b4,b5,b6,b7);
	return (i*0x100000000)+j;
end

local dword2bytes = function(i)
	local b4,b5,b6,b7 = word2bytes(i);
	local b0,b1,b2,b3 = word2bytes(Math.floor(i/0x100000000));
	return b0,b1,b2,b3,b4,b5,b6,b7;
end




local SHA2_256 = function()

	local queue = Queue();

	local h0 = 0x6a09e667;
	local h1 = 0xbb67ae85;
	local h2 = 0x3c6ef372;
	local h3 = 0xa54ff53a;
	local h4 = 0x510e527f;
	local h5 = 0x9b05688c;
	local h6 = 0x1f83d9ab;
	local h7 = 0x5be0cd19;

	local public = {};

	local processBlock = function()
		local a = h0;
		local b = h1;
		local c = h2;
		local d = h3;
		local e = h4;
		local f = h5;
		local g = h6;
		local h = h7;

		local w = {};

		for i=0,15 do
			w[i] = bytes2word(queue.pop(),queue.pop(),queue.pop(),queue.pop());
		end

		for i=16,63 do
			local s0 = XOR(RROT(w[i-15],7), XOR(RROT(w[i-15],18), RSHIFT(w[i-15],3)));
			local s1 = XOR(RROT(w[i-2],17), XOR(RROT(w[i-2], 19), RSHIFT(w[i-2],10)));
			w[i] = AND(w[i-16] + s0 + w[i-7] + s1, 0xFFFFFFFF);
		end

		for i=0,63 do
			local s1 = XOR(RROT(e,6), XOR(RROT(e,11),RROT(e,25)));
			local ch = XOR(AND(e,f), AND(NOT(e),g));
			local temp1 = h + s1 + ch + CONSTANTS[i+1] + w[i];
			local s0 = XOR(RROT(a,2), XOR(RROT(a,13), RROT(a,22)));
			local maj = XOR(AND(a,b), XOR(AND(a,c), AND(b,c)));
			local temp2 = s0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		end

		h0 = AND(h0 + a, 0xFFFFFFFF);
		h1 = AND(h1 + b, 0xFFFFFFFF);
		h2 = AND(h2 + c, 0xFFFFFFFF);
		h3 = AND(h3 + d, 0xFFFFFFFF);
		h4 = AND(h4 + e, 0xFFFFFFFF);
		h5 = AND(h5 + f, 0xFFFFFFFF);
		h6 = AND(h6 + g, 0xFFFFFFFF);
		h7 = AND(h7 + h, 0xFFFFFFFF);
	end

	public.init = function()
		queue.reset();

		h0 = 0x6a09e667;
		h1 = 0xbb67ae85;
		h2 = 0x3c6ef372;
		h3 = 0xa54ff53a;
		h4 = 0x510e527f;
		h5 = 0x9b05688c;
		h6 = 0x1f83d9ab;
		h7 = 0x5be0cd19;

		return public;
	end

	public.update = function(bytes)
		for b in bytes do
			queue.push(b);
			if queue.size() >= 64 then processBlock(); end
		end

		return public;
	end

	public.finish = function()
		local bits = queue.getHead() * 8;

		queue.push(0x80);
		while ((queue.size()+7) % 64) < 63 do
			queue.push(0x00);
		end

		local b0,b1,b2,b3,b4,b5,b6,b7 = dword2bytes(bits);

		queue.push(b0);
		queue.push(b1);
		queue.push(b2);
		queue.push(b3);
		queue.push(b4);
		queue.push(b5);
		queue.push(b6);
		queue.push(b7);

		while queue.size() > 0 do
			processBlock();
		end

		return public;
	end

	public.asBytes = function()
		local  b0, b1, b2, b3 = word2bytes(h0);
		local  b4, b5, b6, b7 = word2bytes(h1);
		local  b8, b9,b10,b11 = word2bytes(h2);
		local b12,b13,b14,b15 = word2bytes(h3);
		local b16,b17,b18,b19 = word2bytes(h4);
		local b20,b21,b22,b23 = word2bytes(h5);
		local b24,b25,b26,b27 = word2bytes(h6);
		local b28,b29,b30,b31 = word2bytes(h7);


		return {  b0, b1, b2, b3, b4, b5, b6, b7, b8, b9,b10,b11,b12,b13,b14,b15
				,b16,b17,b18,b19,b20,b21,b22,b23,b24,b25,b26,b27,b28,b29,b30,b31};
	end

	public.asHex = function()
		local  b0, b1, b2, b3 = word2bytes(h0);
		local  b4, b5, b6, b7 = word2bytes(h1);
		local  b8, b9,b10,b11 = word2bytes(h2);
		local b12,b13,b14,b15 = word2bytes(h3);
		local b16,b17,b18,b19 = word2bytes(h4);
		local b20,b21,b22,b23 = word2bytes(h5);
		local b24,b25,b26,b27 = word2bytes(h6);
		local b28,b29,b30,b31 = word2bytes(h7);

		local fmt = "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"

		return String.format(fmt, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9,b10,b11,b12,b13,b14,b15
				,b16,b17,b18,b19,b20,b21,b22,b23,b24,b25,b26,b27,b28,b29,b30,b31);
	end

	return public;

end

return SHA2_256;

]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
assert(not sources["lockbox"],"module already exists")sources["lockbox"]=([===[-- <pack lockbox> --
local Lockbox = {};

--[[
package.path =  "./?.lua;"
				.. "./cipher/?.lua;"
				.. "./digest/?.lua;"
				.. "./kdf/?.lua;"
				.. "./mac/?.lua;"
				.. "./padding/?.lua;"
				.. "./test/?.lua;"
				.. "./util/?.lua;"
				.. package.path;
]]--
Lockbox.ALLOW_INSECURE = false;

Lockbox.insecure = function()
	assert(Lockbox.ALLOW_INSECURE,"This module is insecure!  It should not be used in production.  If you really want to use it, set Lockbox.ALLOW_INSECURE to true before importing it");
end

return Lockbox;
]===]):gsub('\\([%]%[]===)\\([%]%[])','%1%2')
local add
if not pcall(function() add = require"aioruntime".add end) then
        local loadstring=_G.loadstring or _G.load; local preload = require"package".preload
	add = function(name, rawcode)
		if not preload[name] then
		        preload[name] = function(...) return assert(loadstring(rawcode), "loadstring: "..name.." failed")(...) end
		else
			print("WARNING: overwrite "..name)
		end
        end
end
for name, rawcode in pairs(sources) do add(name, rawcode, priorities[name]) end
end; --}};
do -- preload auto aliasing...
	local p = require("package").preload
	for k,v in pairs(p) do
		if k:find("%.init$") then
			local short = k:gsub("%.init$", "")
			if not p[short] then
				p[short] = v
			end
		end
	end
end
do
	local Lockbox = require"lockbox"
	Lockbox.ALLOW_INSECURE = true
end

local Stream = require("lockbox.util.stream")
local Digest = require("lockbox.digest.sha2_256")
local String = require("string")

local function sha256sum(message)
	return Digest().update(Stream.fromString(message)).finish().asHex()
end
return sha256sum
