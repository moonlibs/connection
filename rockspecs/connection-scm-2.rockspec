package = 'connection'
version = 'scm-2'

source  = {
    url    = 'git://github.com/moonlibs/connection.git';
    branch = 'master';
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
