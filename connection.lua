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
]]

local C = ffi.C

local iovec = ffi.typeof('struct iovec')
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


function M:_init(host, port, opt)
	self.host = host;
	self.port = tonumber(port)
	opt = opt or {}
	
	self.timeout = tonumber(opt.timeout) or 1/3
	
	if opt.autoconnect ~= nil then
		self._auto = opt.autoconnect
	else
		self._auto = true
	end
	
	if opt.reconnect ~= nil then
		if opt.reconnect then
			self._reconnect = tonumber(opt.reconnect)
		else
			self._reconnect = false
		end
	else
		self._reconnect = 1/3
	end
	
	self.maxbuf = opt.maxbuf or 2*1024*1024
	self.rbuf = ffi.new('char[?]', self.maxbuf)
	self.avail = 0ULL

	self.wsize = 32
	local osz = self.wsize
	self.wbuf = ffi.new('struct iovec[?]', self.wsize)

	self.wcur = 0
	self.wstash = {}

	self.connwait = setmetatable({},{__mode = "kv"})
	--[[ -- FIXME
	if opt.deadly or opt.deadly == nil then
		box.reload:register(self)
	end
	]]
end

function M:log(l,msg,...)
	msg = tostring(msg)
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
	if self.ww then if self.ww ~= fiber.self() then pcall(fiber.cancel,self.ww) end self.ww = nil end
	if self.rw then if self.rw ~= fiber.self() then pcall(fiber.cancel,self.rw) end self.rw = nil end
	if self.s  then self.s:close() self.s = nil end

	self.wcur   = 0
	self.wstash = {}
	self.avail  = 0ULL

	self.lasterror = errno.strerror(e)
	for k in pairs(self.connwait) do
		k:put(false)
		self.connwait[k] = nil
	end
end

function M:destroy()
	self:_cleanup(0)
	local name = self.host..':'..self.port
	for k in pairs(self) do
		self[k] = nil
	end
	setmetatable(self,{
		__index = function(s,n)
			log.error("access to `"..n.."' on destroyed con "..name)
			fiber.cancel(fiber.self())
		end,
		__newindex = function(s,n)
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
	-- TODO: stop all fibers
	self:_cleanup(e)
	if self._reconnect then
		self.state = RECONNECTING
		if self.on_connfail then
			fiber.create(function(self) fiber.name("net.cb") self:on_connfail(errno.strerror(e)) end,self)
		end
		fiber.sleep(self._reconnect)
		self:connect()
	else
		self.state = NOTCONNECTED
		fiber.create(function(self) fiber.name("net.cb") self:on_disconnect(errno.strerror(e)) end,self)
	end
end

function M:on_connect_reset(e)
	self:log('W',"connection reset:",errno.strerror(e))
	-- TODO: stop all fibers
	self:_cleanup(e)
	
	if self._reconnect then
		self.state = NOTCONNECTED -- was RECONNECTING
		fiber.create(function(self) fiber.name("net.cb") self:on_disconnect(errno.strerror(e)) end,self)
		fiber.sleep(0)
		self:connect()
	else
		self.state = NOTCONNECTED
		fiber.create(function(self) fiber.name("net.cb") self:on_disconnect(errno.strerror(e)) end,self)
	end
end

function M:on_read(is_last)
	self:log('D',"on_read (last:",is_last,") ",ffi.string(self.rbuf,self.ravail))
	self.avail = 0ULL
end

function M:on_connect_io()
	local err = self.s:getsockopt('SOL_SOCKET', 'SO_ERROR');
	if err ~= 0 then
		-- OLD TODO: error handling
		self:on_connect_failed( err )
		return
	end
	self.state = CONNECTED;
	
	local weak = setmetatable({}, { __mode = "kv" })
	weak.self = self
	
	self.rw = fiber.create(function (weak)
		fiber.name("net.rw")
		local s = weak.self.s
		local fd = s:fd()
		local oft = 0ULL
		local sz  = ffi.sizeof(weak.self.rbuf)
		while weak.self do
			local self = weak.self
			local rd = C.read(fd, self.rbuf + oft, sz - oft)
			-- local rd = C.read(s.socket.fd, self.rbuf + oft, 1)
			if rd >= 0 then
				-- print("read ",rd)
				self.avail = self.avail + rd;
				local avail = self.avail

				local status, err = pcall(self.on_read, self, rd == 0)
				if not status then
					self:log('E', 'on_read raised an error: ', err)
					self:on_connect_reset(errno.EINVAL) -- errno.EINVAL = 22
				end

				local pkoft = avail - self.avail
				-- print("avail ",avail, " -> ", self.avail, " pkoft = ", pkoft)


				if self.avail > 0 then
					if self.avail == self.maxbuf then
						self:on_connect_reset(errno.EMSGSIZE)
						return
					end
					oft = self.avail
					-- print("avail ",avail, " -> ", self.avail, " pkoft = ", pkoft)
					C.memmove(self.rbuf,self.rbuf + pkoft,oft)
				else
					if rd == 0 then
						self:on_connect_reset(errno.ECONNABORTED)
						return
					end
					oft = 0
				end
			elseif errno_is_transient[errno()] then
				s:readable()
			else
				-- print( errno.strerror( errno() ))
				self:on_connect_reset(s:errno())
				return
			end
		end
	end,weak)
	for k,v in pairs(self.connwait) do
		k:put(true)
		self.connwait[k] = nil
	end
	fiber.create(function(self) fiber.name("net.cb") self:on_connected() end,self)
end

function M:connect()
	fiber.create(function()
		assert(type(self) == 'table',"object required")
		
		if self.state == NOTCONNECTED then
			self.state = CONNECTING;
		end
		-- connect timeout
		assert(not self.s, "Already have socket")
		
		local ai = socket.getaddrinfo( self.host, self.port, self.timeout, {
			['type'] = 'SOCK_STREAM',
		} )
		
		if ai and #ai > 0 then
			--print(dumper(ai))
		else
			self:on_connect_failed( errno() == 0 and errno.ENXIO or errno() )
			return
		end
		
		local ainfo = ai[1]
		local s = socket( ainfo.family, ainfo.type, ainfo.protocol )
		if not s then
			self:on_connect_failed( errno() )
			return
		end
		--print("created socket ",s, " ",s:nonblock())
		s:nonblock(true)
		s:linger(1,0)
		
		while true do
			if s:sysconnect( ainfo.host, ainfo.port ) then
				self.s = s
				--print("immediate connected")
				self:on_connect_io()
				return
			else
				if s:errno() == errno.EINPROGRESS
				or s:errno() == errno.EALREADY
				or s:errno() == errno.EWOULDBLOCK
				then
					self.s = s
					
					-- io/w watcher
					assert(not self.ww, "ww already set")
					
					local weak = setmetatable({}, { __mode = "kv" })
					weak.self = self
					
					self.ww =
					fiber.create(function(weak)
						if not weak.self then s:close() return end
						fiber.name("C."..weak.self.port..'.'..weak.self.host)
						local wr = s:writable(weak.self.timeout)
						collectgarbage()
						if not weak.self then s:close() return end
						
						if wr then
							weak.self.ww = nil
							weak.self:on_connect_io()
							return
						else
							weak.self.ww = nil
							weak.self:on_connect_failed( errno.ETIMEDOUT )
							return
						end
					end,weak)
					return
				elseif s:errno() == errno.EINTR then
					-- again
				else
					self:on_connect_failed( s:errno() )
					return
				end
			end
		end
		
	end)
end

function M:_wbuf_realloc( ... )
	local old = self.wbuf
	local osz = self.wsize
	self.wsize = osz * 2
	local nsz = self.wsize
	self.wbuf = ffi.new('struct iovec[?]', self.wsize)
	C.memcpy(self.wbuf, old, self.wcur * ffi.sizeof(self.wbuf[0]))
end

function M:write( buf )
	self:push_write(buf)
	self:flush()
end

function M:push_write( buf, len )
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
	assert(type(self) == 'table',"object required")
	
	if self.state ~= CONNECTED then
		print("flush in state ",S2S[self.state])
		if self._auto then
			if self.state == nil then
				self:connect()
			end
		end
		local connected = false
		if self.state ~= RECONNECTING then
			local ch = fiber.channel(1)
			self.connwait[ ch ] = ch
			connected = ch:get( self.timeout )
		end
		if not connected then
			fiber.sleep(0)
			error("Not connected for flush ("..tostring(self.state)..")",2)
		end
	end

	if self.flushing then return end
	self.flushing = true
	fiber.sleep(0)

	if self:_writev() then self.flushing = false return end

	local weak = setmetatable({}, { __mode = "kv" })
	weak.self = self

	fiber.create(function(weak)
		fiber.name("W."..weak.self.port..'.'..weak.self.host)
		local s = weak.self.s
		local timeout = weak.self.timeout
		while weak.self do
			if s:writable() then
				if not weak.self then break end
				if weak.self:_writev() then break end
			end
		end
		if weak.self then
			weak.self.flushing = false
		end
	end,weak)
end

return M
