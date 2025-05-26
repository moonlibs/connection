# Connection - Base Class for TCP Connections

A Lua module providing a foundation for managing TCP socket connections in Tarantool applications. This library offers an object-oriented approach to handling network connections with support for asynchronous operations, automatic reconnection, and customizable event handling.

## Features

- Asynchronous TCP connection management
- Automatic reconnection with configurable timeout
- Buffer management for both reading and writing
- Event-based architecture with callbacks
- Non-blocking I/O

## Installation

### Using Tarantool Rocks

```bash
tt rocks --server https://moonlibs.org install connection
```

### Manual Installation

Clone the repository and install using the rockspec:

```bash
git clone https://github.com/moonlibs/connection
cd connection
tt rocks make
```

## Usage

### Basic Connection

```lua
local connection = require('connection')

-- Create a new connection
local conn = connection.new('example.com', 8080)

-- Wait for connection to be established (if needed)
conn.connwait:get(timeout)

-- Send data
conn:push_write("Hello, server!")
conn:flush()

-- Close connection when done
conn:close()
```

### Connection Options

```lua
local default_options = {
    timeout = 1/3,           -- Connection and request timeout in seconds
    autoconnect = true,      -- Connect immediately when created
    reconnect = 1/3,         -- Reconnect after 1/3 seconds if connection fails
    maxbuf = 2 * 1024 * 1024 -- 2MB read buffer size for read
}

local conn = connection.new('example.com', 8080, {
    timeout = 1,             -- Connection and request timeout in seconds
    autoconnect = true,      -- Connect immediately when created
    reconnect = 0.5,         -- Reconnect after 0.5 seconds if connection fails
    maxbuf = 2 * 1024 * 1024 -- 2MB read buffer size for read
})
```

### Custom Event Handlers

```lua
local obj = require('obj')
local connection = require('connection')

local MyConnection = obj.class({}, 'MyConnection', connection)

function MyConnection:on_connected()
    self:log('I', 'Successfully connected!')
    -- Initialize session, authenticate, etc.
end

function MyConnection:on_disconnect(err)
    self:log('W', 'Disconnected: %s', err)
    -- Clean up resources
end

function MyConnection:on_read(is_last)
    -- Process received data
    local data = ffi.string(self.rbuf, self.avail)
    self:log('D', 'Received data: %s', data)

    -- Important: reset buffer position after processing
    self.avail = 0
end

-- Create instance of your connection
local conn = MyConnection:new('example.com', 8080)
```

## Connection States

The connection can be in one of the following states:

- `NOTCONNECTED` (0) - Initial state, not connected
- `CONNECTING` (1) - Connection attempt in progress
- `CONNECTED` (2) - Successfully connected
- `RECONNECTING` (3) - Attempting to reconnect after failure

You can check the current state:

```lua
if conn.state == connection.S2S.CONNECTED then
    -- Connection is established
end
```

## API Reference

### Methods (all methods never yields)

- `new(host, port, options)` - Create a new connection
- `connect()` - Initiate connection
- `push_write(buf, len)` - Queue data to be sent, reallocates write buffer
- `flush()` - Send queued data
- `close()` - Close the connection, connection can be reused
- `destroy()` - Clean up resources, makes connection unusable
- `fdno()` - Returns file descriptor (or -1)

### Callbacks (executed in separate fiber)

- `on_connected()` - Called when connection is established, executed in separate fiber
- `on_disconnect(err: string)` - Called when connection is closed, executed in separate fiber
- `on_connect_failed(errno_code)` - Called when connection attempt fails, reconnection logic is performed here
- `on_connect_reset(errno_code)` - Called when connection is reset (closed due to an error)

### Reading data

- `on_read(is_last)` - Called when data is available for reading, from rw (read worker) fiber.
  - **Important**: `on_read` is called directly from the read worker fiber. If your callback yields (using `fiber.sleep()` or other yielding operations), reading from the socket is stopped until the callback returns.
  - If an exception is raised inside `on_read`, the connection will be reset. The connection can be reestablished automatically if the `reconnect` option is set.

### Protected methods

- `_cleanup(errno_code)` - Executes cleanup of all resources, closes socket, cancels fibers, drains buffers

## Example: Echo Client

Here's a simple echo client implementation that demonstrates basic usage:

```lua
local connection = require('connection')
local fiber = require('fiber')
local ffi = require('ffi')
local obj = require('obj')

local EchoClient = obj.class({}, 'EchoClient', connection)

function EchoClient:on_connected()
    self:log('I', 'Connected to echo server')
    -- Send a message when connected
    self:push_write("Hello, Echo Server!\n")
    self:flush()
end

function EchoClient:on_read(is_last)
    -- Process the received echo response
    local data = ffi.string(self.rbuf, self.avail)
    self:log('I', 'Received echo: %s', data)

    -- Clear the buffer after processing
    self.avail = 0

    -- Send another message
    if not is_last then
        -- yielding in on_read callback stops read from socket.
        fiber.sleep(1)
        self:push_write("Another message!\n")
        self:flush()
    end
end

function EchoClient:on_disconnect(err)
    self:log('W', 'Disconnected from echo server: %s', err)
end

-- Usage example
local function test_echo_client()
    local client = EchoClient:new('localhost', 7777)
    client.connwait:get(2)  -- Wait up to 2 seconds for connection

    -- Keep the client running for a while
    fiber.sleep(5)

    -- Close the connection
    client:close()
end

fiber.create(test_echo_client)
```

## Real-World Examples

Some real world examples

[connection-legacy](https://github.com/moonlibs/connection-legacy) repository, which implements a backward compatible API on top of this module.

[connection-scribe](https://github.com/moonlibs/connection-scribe) repository, which implements Scribe protocol

[tarantool1.5-replica](https://github.com/ochaton/migrate/blob/master/migrate/replica.lua) repository, which implements replication protocol of Tarantool 1.5
