local t = require('luatest')
local fiber = require('fiber')
local json  = require('json')
local g = t.group('basic')

local username = 'guest'
local password = ''

---@type luatest.server
local server = t.Server:new({
	alias = 'server',
	box_cfg = {
		listen = '127.0.0.1:3301',
	},
	net_box_port = 3301,
	net_box_uri = '127.0.0.1:3301',
})

g.before_all(function()
	server:start({wait_until_ready = true})
end)

g.after_all(function()
	server:stop()
end)

local connection = require 'connection'

function g.test_connect()
	---@type connection
	local cnn = connection:new(server.net_box.host, server.net_box.port)
	cnn.connwait:get(1)
	t.assert_equals(cnn.state, connection.S2S.CONNECTED, 'connection has been established')
	cnn:close()
	t.assert_equals(cnn.state, connection.S2S.NOTCONNECTED, 'connection has been closed')
end

---@class connection.greeter: connection
local greeter = require 'obj'.class({}, 'connection.greeter', connection)

function greeter:on_connect_io()
	self:super(greeter, 'on_connect_io')()
	self.stage = 'greeting'
end

function greeter:on_greeting_read()
	local avail = self.avail
	local greeting_size = 128
	if avail < greeting_size then return end

	local ffi = require 'ffi'
	local str = ffi.string(self.rbuf, greeting_size)
	self.avail = avail - greeting_size -- consume the greeting

	local _, salt_b64 = unpack(string.split(str, '\n'))
	local digest = require 'digest'

	local salt = digest.base64_decode(salt_b64):sub(1, 20)
	local step1 = digest.sha1(password)
	local step2 = digest.sha1(step1)
	local step3 = digest.sha1(salt .. step2)

	local function xor(s1, s2, n)
		local r = table.new(n, 0)
		for i = 1, n do
			r[i] = string.char(bit.bxor(s1:byte(i), s2:byte(i)))
		end
		return table.concat(r, '')
	end

	local scramble = xor(step1, step3, #salt)

	-- now construct auth packet
	local msgpack = require('msgpack')
	local key = {
		REQUEST_TYPE = 0x00,
		SYNC = 0x01,
		TUPLE = 0x21,
		USER_NAME = 0x23,
	}
	local val = {
		AUTH = 0x07,
	}
	local hdr = {
		[key.REQUEST_TYPE] = val.AUTH,
		[key.SYNC] = 0x01,
	}
	local bdy = {
		[key.USER_NAME] = username,
		[key.TUPLE] = {'chap-sha1', scramble},
	}
	local buf = msgpack.encode(hdr) .. msgpack.encode(bdy)
	local size = msgpack.encode(#buf)
	local pkt = table.concat({
		string.char(0xce),
		-- prepend \0-bytes to buffer
		("\x00\x00\x00\x00"):sub(1, 4 - #size) .. size,
		buf
	},'')

	self:push_write(pkt)
	self.stage = 'fetching_schema'
	self:flush()
end

function greeter:on_fetching_schema_read(is_last)
	local msgpack = require('msgpack')

	local ptr = self.rbuf
	local avail = tonumber(self.avail)
	local tail = ptr + avail

	local sz
	sz, ptr = msgpack.decode(ptr, tonumber(tail-ptr))
	if sz == nil then
		-- not enough data
		return
	end
	self:log('D', 'size:%s', sz)

	if avail < sz then
		-- not enough data
		self:log('D', 'not enough data, need %s, have %s', sz, avail)
		return
	end

	local hdr
	hdr, ptr = msgpack.decode(ptr, tonumber(tail-ptr))
	if hdr == nil then
		-- not enough data
		return
	end
	self:log('D', 'hdr:%s', json.encode(hdr))

	local bdy
	bdy, ptr = msgpack.decode(ptr, tonumber(tail-ptr))
	if bdy == nil then
		-- not enough data
		return
	end
	self:log('D', 'bdy:%s', json.encode(bdy))
	self.avail = tail - ptr

	self.on_schema:put({
		header = hdr,
		body = bdy,
	})
end

---Tarantool greeter
function greeter:on_read(is_last)
	if self.stage == 'greeting' then
		return self:on_greeting_read(is_last)
	elseif self.stage == 'fetching_schema' then
		return self:on_fetching_schema_read(is_last)
	else
		self:log('E', 'unknown stage %s', self.stage)
		self.avail = 0
	end
end

function g.test_greeting()
	local cnn = greeter:new(server.net_box.host, server.net_box.port)
	cnn.on_schema = fiber.channel()
	cnn.connwait:get(1)
	t.assert_equals(cnn.state, connection.S2S.CONNECTED, 'connection has been established')

	local packet = cnn.on_schema:get(5)
	t.assert(packet, "packet with schema must be received")

	local schema_version = server:exec(function()
		return box.info.schema_version or box.internal.schema_version()
	end)

	t.assert_items_equals(packet.header, {
		[0x00] = 0x00, -- REQUEST_TYPE:OK
		[0x01] = 0x01, -- SYNC:1
		[0x05] = schema_version,   -- SCHEMA_ID:83
	}, "packet.header is okay")

	t.assert_items_equals(packet.body, {}, "packet body is empty")
	t.assert_equals(cnn.state, connection.S2S.CONNECTED, 'connection has been established')
end
