std="tarantool"

codes=true
max_line_length=140
include_files = {"connection.lua"}

ignore = {
	"212", -- unused argument
	"431", -- shadwing upvalue
	"432", -- shadowing upvalue argument
	"542", -- empty if branch
}
