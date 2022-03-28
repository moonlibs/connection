--[[
***           This is legacy rockspec
***   Please, for this version refer instead to
***       rockspecs/connection-scm-1.rockspec
]]

package = 'connection'
version = 'scm-1'

source  = {
    url    = 'git+https://github.com/moonlibs/connection.git';
    branch = 'v1';
}

description = {
    summary  = "Base class for tcp connections";
    detailed = "Base class for tcp connections";
    homepage = 'https://github.com/moonlibs/connection.git';
    license  = 'Artistic';
    maintainer = "Mons Anderson <mons@cpan.org>";
}

dependencies = {
    'lua >= 5.1';
    'obj >= 0';
}

build = {
    type = 'builtin',
    modules = {
        ['connection'] = 'connection.lua';
    }
}
