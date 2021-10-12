gCflags = ARGUMENTS.get('CFLAGS', '-Wall -Wextra -O3 -fomit-frame-pointer')
gCxxflags = ARGUMENTS.get('CXXFLAGS', gCflags + ' -fno-exceptions -fno-rtti')
vars = Variables()
vars.Add('CC')
vars.Add('CXX')

env = Environment(CFLAGS = gCflags, CXXFLAGS = gCxxflags, variables = vars)

sourceFiles = Split('''encryption.cpp fwunpack.cpp get_encrypted_data.cpp get_normal_data.cpp keydata.cpp lz77.cpp part345_comp.cpp''')

conf = env.Configure()

conf.Finish()

shlib = env.SharedLibrary('fwunpack', sourceFiles, CXXFLAGS = env['CXXFLAGS'], LINKFLAGS = env['LINKFLAGS'] + ' -s', SHLIBPREFIX = "lib")

env.Default(shlib)
