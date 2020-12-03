local _NAME = ...

local obj = require 'obj'
local ffi = require 'ffi'

local log = require 'log'
local fiber = require 'fiber'
local errno = require 'errno'
local socket = require 'socket'

if not pcall(ffi.typeof,"struct iovec") then
	ffi.cdef[[
		struct iovec {
			void  *iov_base;
			size_t iov_len;
		};
	]]
end

ffi.cdef [[
	char *strerror(int errnum);
	ssize_t read(int fd, void *buf, size_t count);
	void *memcpy(void *dest, const void *src, size_t n);
	void *memmove(void *dest, const void *src, size_t n);
	ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
	void *calloc(size_t nmemb, size_t size);
	void free(void *ptr);
]]

local C = ffi.C

local iovec = ffi.typeof('struct iovec') -- FIXME it is used once!
local IOVSZ = ffi.sizeof(iovec)

local NOTCONNECTED = 0;
local CONNECTING   = 1;
local CONNECTED    = 2;
local RECONNECTING = 3;

local M = obj.class({},_NAME)

local S2S = {
	[NOTCONNECTED]  = 'NOTCONNECTED',
	[CONNECTING]    = 'CONNECTING',
	[CONNECTED]     = 'CONNECTED',
	[RECONNECTING]  = 'RECONNECTING',
}
M.S2S = S2S

local errno_is_transient = {
	[errno.EINPROGRESS] = true;
	[errno.EAGAIN] = true;
	[errno.EWOULDBLOCK] = true;
	[errno.EINTR] = true;
}

--[[
options:
	timeout -
	autoconnect -
	reconnect -
	maxbuf -

internal fields:
	host - host connect to
	port - port connect to
	_reconnect - should we reconnect on connection reset?
	maxbuf - read buffer size. Although it is named 'maxbuf', buffer is not rellocatable.
	rbuf - read buffer
	avail - Actual data length in buffer
	state - connection stat, valid values are:
		NOTCONNECTED
		CONNECTED
		CONNECTING
		RECONNECTING
	_flush
	_auto
	_gen

]]
function M:_init(host, port, opt)
	self.host = host;
	self.port = tonumber(port)
	opt = opt or {}

	self.timeout = tonumber(opt.timeout) or 1/3

	if opt.reconnect ~= nil then
		if opt.reconnect then
			self._reconnect = tonumber(opt.reconnect)
		else
			self._reconnect = false
		end
	else
		self._reconnect = 1/3
	end

	if opt.autoconnect ~= nil then
		self._auto = opt.autoconnect
	else
		self._auto = true
	end

	self.state = NOTCONNECTED
	self.maxbuf = opt.maxbuf or 2*1024*1024
	self.rbuf = ffi.cast('char *', ffi.C.calloc(1, self.maxbuf))

	do
		local firstcall = true
		ffi.gc(self.rbuf, function(ptr)
			if not firstcall then
				print("Called double __gc on:", tostring(ptr))
				return
			end
			firstcall = false
			ffi.C.free(ptr)
		end)
	end
	self.avail = 0ULL
	self._gen = 0

	self.wsize = 32
	self.wbuf = ffi.new('struct iovec[?]', self.wsize)

	self.wcur = 0
	self.wstash = {}

	self._flush = fiber.channel(0)

	self.connwait = fiber.channel(0)

	if self._auto then
		self:connect()
	end
end

function M:log(l,msg,...)
	msg = tostring(msg)
	-- FIXME it's a bad pattern. We should always use format
	if string.match(msg,'%%') then
		msg = string.format(msg,...)
	else
		local m = { msg }
		for _,v in pairs({...}) do
			table.insert(m, tostring(v))
		end
		msg = table.concat(m,' ')
	end
	log.info( "[%s] {%s:%s} %s", l, self.host, self.port, msg )
end

function M:fdno()
	if self.s then
		return self.s:fd()
	else
		return -1
	end
end

function M:_stringify()
	return string.format("cnn(%s:%s : %s:%s : %s)",self:fdno(),self.state,self.host,self.port,self.__id)
end

function M:desc()
	return tostring(self.host) .. ':' .. tostring(self.port) .. '/' .. self:fdno()
end

function M:on_connected()
	self:log("D", "called default on_connected")
end

function M:on_disconnect(e)
	self:log("D", "called default on_disconnect: %s", e)
end

function M:_cleanup(e)
	self.state = NOTCONNECTED
	if self.ww then if self.ww ~= fiber.self() then pcall(fiber.cancel,self.ww) end self.ww = nil end
	if self.rw then if self.rw ~= fiber.self() then pcall(fiber.cancel,self.rw) end self.rw = nil end
	if self.s  then self.s:close() self.s = nil end

	self.wcur   = 0
	self.wstash = {}
	self.avail  = 0ULL

	self.lasterror = errno.strerror(e)

	while self.connwait:put(false, 0) do end
end

function M:destroy()
	self:_cleanup(0)
	local name = self.host..':'..self.port
	for k in pairs(self) do
		self[k] = nil
	end
	setmetatable(self,{
		__index = function(_,n)
			log.error("access to `"..n.."' on destroyed con "..name)
			fiber.cancel(fiber.self())
		end,
		__newindex = function(_,n)
			log.error("access to `"..n.."' on destroyed con"..name)
			fiber.cancel(fiber.self())
		end
	})
end

function M:close()
	self:_cleanup(0)
	self:log('I', self.host..':'..self.port..' closed')
end

function M:on_connect_failed(e)
	self:log('E','Connect failed:', errno.strerror(e))
	if self.state == CONNECTING then
		self:_cleanup(e)
		if self.state == NOTCONNECTED then
			if self._reconnect then
				self.state = RECONNECTING
				if self.on_connfail then
					fiber.create(function(cnn) fiber.name("net.cb") cnn:on_connfail(errno.strerror(e)) end,self)
				end
				fiber.sleep(self._reconnect)
				if self.state == RECONNECTING then
					self.state = NOTCONNECTED
					self:connect()
				end
			else
				-- self.state = NOTCONNECTED -- already
				fiber.create(function(cnn) fiber.name("net.cb") cnn:on_disconnect(errno.strerror(e)) end,self)
			end
		end
	end
end

function M:on_connect_reset(e)
	self:log('W',"connection reset:",errno.strerror(e))
	if self.state == CONNECTED then
		-- TODO: stop all fibers
		self:_cleanup(0)

		if self._reconnect then
			self.state = NOTCONNECTED -- was RECONNECTING
			fiber.create(function(cnn) fiber.name("net.cb") cnn:on_disconnect(errno.strerror(e)) end,self)
			fiber.sleep(0)
			self:connect()
		else
			-- self.state = NOTCONNECTED -- already
			fiber.create(function(cnn) fiber.name("net.cb") cnn:on_disconnect(errno.strerror(e)) end,self)
		end
	end
end

function M:on_read(is_last)
	self:log('D',"on_read (last:",is_last,") ",ffi.string(self.rbuf,self.ravail))
	self.avail = 0ULL
end

function M:on_connect_io()
	do
		local err = self.s:getsockopt('SOL_SOCKET', 'SO_ERROR');
		if err ~= 0 then
			self:on_connect_failed(err)
			return
		end
	end
	self.state = CONNECTED;

	local weak = setmetatable({}, { __mode = "kv" })
	weak.self = self
	--print('----', weak.self.s)

	self.ww = fiber.create(function (weak, gen)
		fiber.name(string.format("net.ww[%s:%s#%d]", weak.self.host, weak.self.port, gen), { truncate = true })
		local s = weak.self.s
		while weak.self and gen == weak.self._gen do
			if s:writable(1) then
				if not weak.self then break end
				if weak.self:_writev() then
					-- The write buffer is drained
					weak.self._flush:get(1)
				end
			end
		end
	end, weak, self._gen)

	self.rw = fiber.create(function (weak, gen)
		fiber.name(string.format("net.rw[%s:%s#%d]", weak.self.host, weak.self.port, gen), { truncate = true })
		local s = weak.self.s
		local fd = s:fd()
		local oft = 0ULL
		local sz  = weak.self.maxbuf
		while weak.self and gen == weak.self._gen do
			local self = weak.self
			local rd = C.read(fd, self.rbuf + oft, sz - oft)
			-- local rd = C.read(s.socket.fd, self.rbuf + oft, 1)
			if rd >= 0 then
				self.avail = self.avail + rd;
				local avail = self.avail

				local status, err = pcall(self.on_read, self, rd == 0)
				if not status then
					self:log('E', 'on_read raised an error: ', err)
					return self:on_connect_reset(errno.EINVAL) -- errno.EINVAL = 22
				end

				local pkoft = avail - self.avail
				-- print("avail ",avail, " -> ", self.avail, " pkoft = ", pkoft)

				-- FIXME: Is it a good idea?
				if self.avail > 0 then
					if self.avail == self.maxbuf then
						return self:on_connect_reset(errno.EMSGSIZE)
					end
					oft = self.avail
					-- print("avail ",avail, " -> ", self.avail, " pkoft = ", pkoft)
					C.memmove(self.rbuf,self.rbuf + pkoft,oft)
				else
					if rd == 0 then
						return self:on_connect_reset(errno.ECONNABORTED)
					end
					oft = 0
				end
			elseif errno_is_transient[errno()] then
				self = nil
				s:readable()
			else
				-- print( errno.strerror( errno() ))
				return self:on_connect_reset(s:errno())
			end
		end
		if s then
			log.error("Close stale socket: %s", s)
			s:close()
		end
	end, weak, self._gen)

	while self.connwait:put(true, 0) do end
	fiber.create(function(cnn) fiber.name("net.cb") cnn:on_connected() end,self)
end

function M:wait_con(timeout)
	if self.state == CONNECTED then
		return true
	end
	-- FIXME move define default timeout in the start of the file
	if self.connwait:get(timeout or self.timeout or 10) then
		return
	else
		-- FIXME Should we use to kinds of error here? There are two cases: it
		-- can be a connection timeout or not called connect method.
		error('Connection timeoud')
	end
end

function M:connect()
	assert(type(self) == 'table',"object required")

	if self.state ~= NOTCONNECTED then
		return (self.state == CONNECTED)
	end

	-- connect timeout
	assert(not self.s, "Already have socket")

	self.state = CONNECTING
	self._gen = self._gen + 1

	local weak = setmetatable({}, { __mode = "kv" })
	weak.self = self

	fiber.create(function(weak)
		-- We don't need to check self because fiber is runned without yielding
		local ai = socket.getaddrinfo( weak.self.host, weak.self.port, weak.self.timeout, {
			['type'] = 'SOCK_STREAM',
		} )

		-- But after getaddrinfo we do need to check the link
		if not weak.self then return end

		if ai and #ai > 0 then
			--print(dumper(ai))
		else
			weak.self:on_connect_failed( errno() == 0 and errno.ENXIO or errno() )
			return
		end

		local ainfo = ai[1]
		local s = socket( ainfo.family, ainfo.type, ainfo.protocol )
		if not s then
			weak.self:on_connect_failed( errno() )
			return
		end

		s:nonblock(true)
		s:linger(1,0)

		while true do
			-- FIXME sysconnect should be not yielding, but we have to dowble check
			-- for traps from tnt team
			if s:sysconnect( ainfo.host, ainfo.port ) then
				weak.self.s = s
				--print("immediate connected")
				weak.self:on_connect_io()
				return
			else
				if s:errno() == errno.EINPROGRESS
				or s:errno() == errno.EALREADY
				or s:errno() == errno.EWOULDBLOCK
				then
					weak.self.s = s

					local wr = s:writable(weak.self.timeout)

					if not weak.self then s:close() return end

					if wr then
						weak.self:on_connect_io()
					else
						weak.self:on_connect_failed( errno.ETIMEDOUT )
					end

					return
				elseif s:errno() == errno.EINTR then
					-- again
					if not weak.self then s:close() return end
				else
					weak.self:on_connect_failed( s:errno() )
					return
				end
			end
		end

	end, weak)
end

function M:_wbuf_realloc()
	local old = self.wbuf
	local osz = self.wsize
	self.wsize = osz * 2
	self.wbuf = ffi.new('struct iovec[?]', self.wsize)
	C.memcpy(self.wbuf, old, self.wcur * ffi.sizeof(self.wbuf[0]))
end

function M:push_write( buf, len )
	if self.state ~= CONNECTED then
		error("Not connected")
	end
	if self.wcur == self.wsize - 1 then
		self:_wbuf_realloc()
	end

	local ffibuf
	if type(buf) == 'cdata' then
		ffibuf = ffi.cast('char *',buf)
	else
		ffibuf = ffi.cast('char *',buf)
	end

	-- print("push_write ",#buf, "; wcur = ",self.wcur, "; wstash = ", #self.wstash, "; buf = ",ffibuf)

	self.wbuf[self.wcur].iov_base = ffibuf
	self.wbuf[self.wcur].iov_len = len or #buf
	table.insert(self.wstash,buf)
	self.wcur = self.wcur + 1
end

function M:_writev()
	if self.wcur == 0 then
		return true
	end
	--- should return true if no more tries should be done
	local wr = C.writev(self.s:fd(), self.wbuf, self.wcur)

	if wr > 0 then
		local len = 0
		for i = 0,self.wcur-1 do
			len = len + self.wbuf[i].iov_len
			local cptr = table.remove(self.wstash,1)
			if len == wr then
				if i == self.wcur - 1 then
					self.wcur = 0
					return true
				else
					self.wcur = self.wcur - (i+1)
					-- print("(1) new wcur = ",self.wcur, ' new wstash = ', #self.wstash)
					C.memmove( self.wbuf, self.wbuf[i+1], self.wcur * IOVSZ )
					return false
				end
			elseif len > wr then
				-- print("len ",len," > ", wr, " wcur = ", self.wcur, " i= ",i)
				local left = len - wr
				local offset = self.wbuf[i].iov_len - left

				table.insert(self.wstash,1,cptr)

				self.wcur = self.wcur - i -- wcur - (i+1) + 1
				-- print("(2) new wcur = ",self.wcur, ' new wstash = ', #self.wstash)
				C.memmove( self.wbuf, self.wbuf[i], self.wcur * IOVSZ )

				self.wbuf[0].iov_base = ffi.cast('char *',ffi.cast('char *',self.wbuf[0].iov_base) + offset)
				self.wbuf[0].iov_len = left
				break -- for
			end
		end
	elseif errno_is_transient[ ffi.errno() ] then
		-- print(errno.strerror( ffi.errno() ))
		-- iowait
	else
		print(errno.strerror( ffi.errno() ))
		self:on_connect_reset( ffi.errno() )
		return true
	end
	-- iowait ?
	return false

end

function M:flush()
	assert(type(self) == 'table', "object required")

	if self.state ~= CONNECTED then
		error("Not connected")
	end

	self._flush:put(true, 0)
end

return M
